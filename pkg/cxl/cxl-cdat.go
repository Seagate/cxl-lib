// Copyright (c) 2023 Seagate Technology LLC and/or its Affiliates

// This file implements the CXL Mailbox related structures and methods based on CXL spec rev3.0
package cxl

import (
	"fmt"
	"os"
	"syscall"
	"time"
	"unsafe"

	"k8s.io/klog/v2"
)

const MB_CHECK_INTERVAL = 100 // Millisecond
const MB_WRITE_INTERVAL = 10  // Millisecond
const MB_READ_INTERVAL = 10   // Millisecond

type DOE_CAP struct {
	doe_cap      *PCIE_DOE_EXT_CAP
	mmap         []byte   // this holds the entire 4k pcie config space ( because mmap has to be 4k aligned )
	dev_mem_file *os.File // this holds the file pointer to the /dev/mem system file
	CDAT_valid   bool
}

func (cdat *DOE_CAP) init(BaseAddr int64) error {
	var err error
	alignedBaseAddr := BaseAddr & 0x7FFFFFFFFFFFF000
	bufSize := 0x1000
	cdat.dev_mem_file, err = os.OpenFile("/dev/mem", os.O_RDWR|os.O_SYNC, 0)
	if err != nil {
		klog.Fatal(err)
	}

	klog.V(DBG_LVL_INFO).Infof("cxl-DOE.init: phyaddr 0x%X size 0x%X", alignedBaseAddr, bufSize)
	cdat.mmap, err = syscall.Mmap(int(cdat.dev_mem_file.Fd()), alignedBaseAddr, bufSize, syscall.PROT_READ|syscall.PROT_WRITE, syscall.MAP_SHARED)
	if err != nil {
		klog.Fatal(err)
	}

	cdat.doe_cap = (*PCIE_DOE_EXT_CAP)(unsafe.Pointer(&cdat.mmap[BaseAddr&0xFFF]))
	klog.V(DBG_LVL_DETAIL).InfoS("cxl-DOE.init", "cdat.doe_cap", cdat.doe_cap)
	cdat.dicover_data_objects()
	klog.V(DBG_LVL_BASIC).Info("cxl-util.CXLDOE initialized")
	return err

}

// ////////////// General DOE flow
func (cdat *DOE_CAP) doe_request(request doe_data_object) {
	klog.V(DBG_LVL_DETAIL).InfoS("cxl-DOE.doe_request", "request", request)

	// send header 1
	hdr1 := uint32(request.DO_Hdr1.Vendor_ID) | uint32(request.DO_Hdr1.DO_type)<<16
	cdat.doe_write_dw(hdr1)
	// send header 2
	cdat.doe_write_dw(uint32(request.DO_Hdr2.Length))
	// send data object
	for _, DW := range request.Data_Object_DW {
		cdat.doe_write_dw(DW)
	}
	cdat.doe_go()

	klog.V(DBG_LVL_DETAIL).InfoS("cxl-DOE.doe_request", "request sent")
}

func (cdat *DOE_CAP) doe_response() doe_data_object {

	hdr1 := parseStruct(u32toByte([]uint32{cdat.doe_read_dw()}), PCIE_DOE_HEADER1{})
	hdr2 := parseStruct(u32toByte([]uint32{cdat.doe_read_dw()}), PCIE_DOE_HEADER2{})

	response := DOE_DATA_OBJECT(uint(hdr2.Length) - 2)
	response.DO_Hdr1 = hdr1
	response.DO_Hdr2 = hdr2
	for i := 0; i < int(hdr2.Length)-2; i++ {
		response.Data_Object_DW[i] = cdat.doe_read_dw()
	}

	return response
}

func (cdat *DOE_CAP) doe_write_dw(val uint32) {
	cdat.doe_cap.DOE_Write_Data_Mailbox = val
	time.Sleep(time.Duration(MB_WRITE_INTERVAL) * time.Millisecond)
	klog.V(DBG_LVL_DETAIL).InfoS("cxl-DOE.doe_write_dw", "DW", val)
}

func (cdat *DOE_CAP) doe_read_dw() uint32 {
	data := cdat.doe_cap.DOE_Read_Data_Mailbox
	time.Sleep(time.Duration(MB_READ_INTERVAL) * time.Millisecond)
	cdat.doe_cap.DOE_Read_Data_Mailbox = 0
	time.Sleep(time.Duration(MB_WRITE_INTERVAL) * time.Millisecond)
	klog.V(DBG_LVL_DETAIL).InfoS("cxl-DOE.doe_read_dw", "DW", data)
	return data
}

func (cdat *DOE_CAP) doe_busy() bool {
	return DOE_STATUS_Busy.read(cdat.doe_cap.DOE_Status) == 1
}

func (cdat *DOE_CAP) doe_go() {
	DOE_CONTROL_Go.write(&cdat.doe_cap.DOE_Control, 1)
}

func (cdat *DOE_CAP) doe_ready() bool {
	return DOE_STATUS_Object_Ready.read(cdat.doe_cap.DOE_Status) == 1
}

func (cdat *DOE_CAP) doe_abort() {
	DOE_CONTROL_Abort.write(&cdat.doe_cap.DOE_Control, 1)
}

// predefined doe functions
func (cdat *DOE_CAP) dicover_data_objects() {
	retry := 0
	maxRetry := 3
	request := DOE_DATA_OBJECT(1)
	request.DO_Hdr1.Vendor_ID = 1 //// PCI_SIG
	request.DO_Hdr1.DO_type = 0   //// DISCOVER
	request.DO_Hdr2.Length = 3
	request.Data_Object_DW[0] = 0
	for request.Data_Object_DW[0] != 0xffff {
		if !cdat.doe_busy() {
			cdat.doe_request(request)
			for !cdat.doe_ready() {
				time.Sleep(time.Duration(MB_CHECK_INTERVAL) * time.Millisecond)
			}
			response := cdat.doe_response()
			discover_response := parseStruct(u32toByte([]uint32{response.Data_Object_DW[0]}), DOE_Discovery_Response{})
			klog.V(DBG_LVL_DETAIL).InfoS("cxl-DOE.dicover_data_objects", "response", response)
			klog.V(DBG_LVL_DETAIL).InfoS("cxl-DOE.dicover_data_objects", "discover_response", discover_response)

			if discover_response.Vendor_Id == CXL_Vendor_ID && discover_response.Data_Object_Protocol == CXL_DOE_PROTOCOL_TABLE_ACCESS {
				cdat.CDAT_valid = true
			}

			request.Data_Object_DW[0] = uint32(discover_response.Next_Index)
			if request.Data_Object_DW[0] == 0 {
				break
			}
		} else {
			if retry > maxRetry {
				klog.V(DBG_LVL_BASIC).InfoS("cxl-DOE.dicover_data_objects", "timeout", retry)
				return
			}
			klog.V(DBG_LVL_DETAIL).InfoS("cxl-DOE.dicover_data_objects", "busy")
			time.Sleep(time.Duration(MB_CHECK_INTERVAL) * time.Millisecond)
			retry++
		}
	}
}

func (cdat *DOE_CAP) doe_request_CDAT(entryHandle uint32) []byte {
	request := DOE_DATA_OBJECT(1)
	request.DO_Hdr1.Vendor_ID = CXL_Vendor_ID
	request.DO_Hdr1.DO_type = CXL_DOE_PROTOCOL_TABLE_ACCESS
	request.DO_Hdr2.Length = 3
	request.Data_Object_DW[0] = CDAT_read_Entry_Request(entryHandle)
	if !cdat.doe_busy() {
		cdat.doe_request(request)
		for !cdat.doe_ready() {
			time.Sleep(time.Duration(MB_CHECK_INTERVAL) * time.Millisecond)
		}
		response := cdat.doe_response()
		klog.V(DBG_LVL_DETAIL).InfoS("cxl-DOE.doe_request_CDAT", "response", response)
		return u32toByte(response.Data_Object_DW)

	} else {
		fmt.Printf("DOE is busy!\n")
		return nil
	}
}

func (cdat *DOE_CAP) PrintAllCDAT() {
	if cdat.CDAT_valid {
		cdat.doe_abort()

		time.Sleep(time.Duration(MB_CHECK_INTERVAL) * time.Millisecond)

		if cdat.doe_busy() {
			fmt.Print("Device DOE is busy!\n")
		} else {

			next_entry := uint32(0)
			for next_entry != 0xffff {
				cdat_buf := cdat.doe_request_CDAT(next_entry)

				//// parse CDAT
				klog.V(DBG_LVL_DETAIL).InfoS("cxl-DOE.PrintAllCDAT", "next_entry", next_entry, "cdat_buf", cdat_buf)

				cdat_response := parseStruct(cdat_buf, CDAT_read_Entry_Response(uint(len(cdat_buf))-4))
				klog.V(DBG_LVL_DETAIL).InfoS("cxl-DOE.PrintAllCDAT", "cdat_response", cdat_response)
				if next_entry == 0 { //// header
					TableEntry := parseStruct(cdat_response.TableEntry, Coherent_Device_Attribute_Table_Header{})
					fmt.Print("\nCoherent_Device_Attribute_Table_Header:\n")
					print_struct_table(TableEntry)
				} else {
					switch cdat_response.TableEntry[0] {
					case CDAT_DSMAS_Struct_Handle:
						TableEntry := parseStruct(cdat_response.TableEntry, CDAT_DSMAS{})
						fmt.Printf("\nDevice Scoped Memory Affinity Structure (DSMAS):\n")
						print_struct_table(TableEntry)
					case CDAT_DSLBIS_Struct_Handle:
						TableEntry := parseStruct(cdat_response.TableEntry, CDAT_DSLBIS{})
						fmt.Printf("\nDevice Scoped Latency and Bandwidth Information Structure (DSLBIS):\n")
						fmt.Printf(DSLBIS_data_string[TableEntry.Data_Type], TableEntry.Entry_Base_Unit*uint64(TableEntry.Entry[0]))
						print_struct_table(TableEntry)
					case CDAT_DSMSCIS_Struct_Handle:
						TableEntry := parseStruct(cdat_response.TableEntry, CDAT_DSMSCIS{})
						fmt.Printf("\nDevice Scoped Memory Side Cache Information Structure (DSMSCIS):\n")
						print_struct_table(TableEntry)
					case CDAT_DSIS_Struct_Handle:
						TableEntry := parseStruct(cdat_response.TableEntry, CDAT_DSIS{})
						fmt.Printf("\nDevice Scoped Initiator Structure (DSIS):\n")
						print_struct_table(TableEntry)
					case CDAT_DSEMTS_Struct_Handle:
						TableEntry := parseStruct(cdat_response.TableEntry, CDAT_DSEMTS{})
						fmt.Printf("\nDevice Scoped EFI Memory Type Structure (DSEMTS):\n")
						print_struct_table(TableEntry)
					case CDAT_SSLBIS_Struct_Handle:
						TableEntry := parseStruct(cdat_response.TableEntry, CDAT_SSLBIS(uint(len(cdat_response.TableEntry)/8-1)))
						fmt.Printf("\nSwitch Scoped Latency and Bandwidth Information Structure (SSLBIS):\n")
						print_struct_table(TableEntry)
					}
				}

				next_entry = uint32(cdat_response.EntryHandle)
			}
		}

	}

}

func (cdat *DOE_CAP) Get_CDAT_DSLBIS_performance() CxlMemAttr {
	memAttr := CxlMemAttr{}
	if cdat.CDAT_valid {
		cdat.doe_abort()

		time.Sleep(time.Duration(MB_CHECK_INTERVAL) * time.Millisecond)

		if cdat.doe_busy() {
			fmt.Print("Device DOE is busy!\n")
		} else {

			next_entry := uint32(0)
			for next_entry != 0xffff {
				cdat_buf := cdat.doe_request_CDAT(next_entry)
				//// parse CDAT
				klog.V(DBG_LVL_DETAIL).InfoS("cxl-DOE.PrintAllCDAT", "next_entry", next_entry, "cdat_buf", cdat_buf)
				cdat_response := parseStruct(cdat_buf, CDAT_read_Entry_Response(uint(len(cdat_buf))-4))
				klog.V(DBG_LVL_DETAIL).InfoS("cxl-DOE.PrintAllCDAT", "cdat_response", cdat_response)
				if next_entry != 0 { // not header
					switch cdat_response.TableEntry[0] {
					case CDAT_DSLBIS_Struct_Handle:
						TableEntry := parseStruct(cdat_response.TableEntry, CDAT_DSLBIS{})
						klog.V(DBG_LVL_DETAIL).InfoS(DSLBIS_data_string[TableEntry.Data_Type], TableEntry.Entry_Base_Unit*uint64(TableEntry.Entry[0]))
						switch TableEntry.Data_Type {
						case 0:
							memAttr.AccessLatencyPs = TableEntry.Entry_Base_Unit * uint64(TableEntry.Entry[0])
						case 1:
							memAttr.ReadLatencyPs = TableEntry.Entry_Base_Unit * uint64(TableEntry.Entry[0])
						case 2:
							memAttr.WriteLatencyPs = TableEntry.Entry_Base_Unit * uint64(TableEntry.Entry[0])
						case 3:
							memAttr.AccessBandwidthMBs = TableEntry.Entry_Base_Unit * uint64(TableEntry.Entry[0])
						case 4:
							memAttr.ReadBandwidthMBs = TableEntry.Entry_Base_Unit * uint64(TableEntry.Entry[0])
						case 5:
							memAttr.WriteBandwidthMBs = TableEntry.Entry_Base_Unit * uint64(TableEntry.Entry[0])
						}

					default:
						continue
					}
				}

				next_entry = uint32(cdat_response.EntryHandle)
			}
		}

	}
	return memAttr
}

// ////// DOE CDAT structure
const CXL_DOE_PROTOCOL_TABLE_ACCESS = 2

type PCIE_DOE_HEADER1 struct {
	Vendor_ID uint16
	DO_type   uint8
	Reserved  uint8
}

type PCIE_DOE_HEADER2 struct {
	Length   bitfield_18b
	Reserved bitfield_14b
}

type doe_data_object struct {
	DO_Hdr1        PCIE_DOE_HEADER1
	DO_Hdr2        PCIE_DOE_HEADER2
	Data_Object_DW []uint32 // up to 256k
}

func DOE_DATA_OBJECT(DW_L uint) doe_data_object {
	slice := make([]uint32, DW_L)
	return doe_data_object{
		Data_Object_DW: slice,
	}
}

var (
	DOE_CAPABILITIES_Interrupt_Support        = u32field{offset: 0, bitwidth: 1}
	DOE_CAPABILITIES_Interrupt_Message_Number = u32field{offset: 1, bitwidth: 11}
	DOE_CONTROL_Abort                         = u32field{offset: 0, bitwidth: 1}
	DOE_CONTROL_Interrupt_Enable              = u32field{offset: 1, bitwidth: 1}
	DOE_CONTROL_Go                            = u32field{offset: 31, bitwidth: 1}
	DOE_STATUS_Busy                           = u32field{offset: 0, bitwidth: 1}
	DOE_STATUS_Interrupt_Status               = u32field{offset: 1, bitwidth: 1}
	DOE_STATUS_Interrupt_Error                = u32field{offset: 2, bitwidth: 1}
	DOE_STATUS_Object_Ready                   = u32field{offset: 31, bitwidth: 1}
)

type PCIE_DOE_EXT_CAP struct {
	PCIE_ext_cap_hdr       uint32
	DOE_Capabilities       uint32
	DOE_Control            uint32
	DOE_Status             uint32
	DOE_Write_Data_Mailbox uint32
	DOE_Read_Data_Mailbox  uint32
}

// // response struct
type DOE_Discovery_Response struct {
	Vendor_Id            uint16
	Data_Object_Protocol uint8
	Next_Index           uint8
}

// // CDAT request and response struct
func CDAT_read_Entry_Request(entryHandle uint32) uint32 {
	// bits 0-7:   Table Access Request Code – 0 to indicate this is a request to read an entry.
	// bits 8-15:  Table Type - 0 - CDAT
	// bits 16-31: EntryHandle - Handle value associated with the entry being requested.
	//             For Table Type = 0, EntryHandle = 0 specifies that the request is for the
	//             CDAT header and EntryHandle>0 indicates the request is for the CDAT
	//             Structure[EntryHandle - 1].

	return 0 | 0<<8 | entryHandle<<16
}

type Coherent_Device_Attribute_Table_Header struct {
	Length   uint32
	Revision uint8
	Checksum uint8
	Reserved [6]uint8
	Sequence uint32
}

// 0 Device Scoped Memory Affinity Structure (DSMAS)
type CDAT_DSMAS struct {
	Type        uint8
	Reserved    uint8
	Length      uint16
	DSMADHandle uint8
	Flags       uint8
	Reserved2   uint16
	DPA_Base    uint64
	DPA_Length  uint64
}

// 1 Device Scoped Latency and Bandwidth Information Structure (DSLBIS)
type CDAT_DSLBIS struct {
	Type            uint8
	Reserved        uint8
	Length          uint16
	Handle          uint8
	Flags           uint8
	Data_Type       uint8
	Reserved2       uint8
	Entry_Base_Unit uint64
	Entry           [3]uint16
	Reserved3       uint16
}

// 2 Device Scoped Memory Side Cache Information Structure (DSMSCIS)
type CDAT_DSMSCIS struct {
	Type                   uint8
	Reserved               uint8
	Length                 uint16
	Handle                 uint8
	Reserved2              [3]uint8
	Memory_Side_Cache_Size uint64
	Cache_Attributes       uint32
}

// 3 Device Scoped Initiator Structure (DSIS)
type CDAT_DSIS struct {
	Type      uint8
	Reserved  uint8
	Length    uint16
	Flags     uint8
	Handle    uint8
	Reserved2 uint16
}

// 4 Device Scoped EFI Memory Type Structure (DSEMTS)
type CDAT_DSEMTS struct {
	Type                          uint8
	Reserved                      uint8
	Length                        uint16
	Handle                        uint8
	EFI_Memory_Type_and_Attribute uint8
	Reserved2                     uint16
	DPA_Offset                    uint64
	DPA_Length                    uint64
}

// 5 Switch Scoped Latency and Bandwidth Information Structure (SSLBIS)
// //  Switch Scoped Latency and Bandwidth Entry (SSLBE)
type CDAT_SSLBE struct {
	Port_X_ID            uint16
	Port_Y_ID            uint16
	Latency_or_Bandwidth uint16
	Reserved             uint16
}

type cdat_sslbis struct {
	Type        uint8
	Reserved    uint8
	Length      uint16
	Data_Type   uint8
	Reserved2   [3]uint8
	SSLBE_Entry []CDAT_SSLBE
}

func CDAT_SSLBIS(entryCnt uint) cdat_sslbis {
	slice := make([]CDAT_SSLBE, entryCnt)
	return cdat_sslbis{
		SSLBE_Entry: slice,
	}
}

type CDAT_header struct {
	Table_Access_Response uint8
	Table_Type            uint8
	EntryHandle           uint16
	TableEntry            []uint8
}

func CDAT_read_Entry_Response(entryCnt uint) CDAT_header {
	slice := make([]uint8, entryCnt)
	return CDAT_header{
		TableEntry: slice,
	}
}

// // CDAT entry type to data struct
const (
	CDAT_DSMAS_Struct_Handle   = iota // 0 Device Scoped Memory Affinity Structure (DSMAS)
	CDAT_DSLBIS_Struct_Handle         // 1 Device Scoped Latency and Bandwidth Information Structure (DSLBIS)
	CDAT_DSMSCIS_Struct_Handle        // 2 Device Scoped Memory Side Cache Information Structure (DSMSCIS)
	CDAT_DSIS_Struct_Handle           // 3 Device Scoped Initiator Structure (DSIS)
	CDAT_DSEMTS_Struct_Handle         // 4 Device Scoped EFI Memory Type Structure (DSEMTS)
	CDAT_SSLBIS_Struct_Handle         // 5 Switch Scoped Latency and Bandwidth Information Structure (SSLBIS)
)

var DSLBIS_data_string = [...]string{
	"DSLBIS Access Latency: %d ps\n",
	"DSLBIS Read Latency: %d ps\n",
	"DSLBIS Write Latency: %d ps\n",
	"DSLBIS Access Bandwidth: %d MB/s\n",
	"DSLBIS Read Bandwidth: %d MB/s\n",
	"DSLBIS Write Bandwidth: %d MB/s\n"}

const DOE_PCIE_ext_cap_ID = 0x2E
