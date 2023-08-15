// Copyright (c) 2023 Seagate Technology LLC and/or its Affiliates

// This file implements the API functions of the cxl library
package cxl

import (
	"bufio"
	"bytes"
	"fmt"
	"os"
	"strconv"
	"strings"
	"syscall"
	"unsafe"

	"k8s.io/klog/v2"

	_ "embed"
)

const (
	DBG_LVL_DEFAUILT    = iota //0
	DBG_LVL_BASIC              //1
	DBG_LVL_INFO               //2
	DBG_LVL_DETAIL             //3
	DBG_LVL_DEEP_DETAIL        //4
)

//go:embed "pci.ids"
var pci_ids string

var PciVendor map[string]string

// Base address of PCI memory mapped configurations
var PCI_MMCONFIG_BASE_ADDR int64

// CxlDevType : The type of the CXL device, ie type 1, 2, 3.
type CxlDevType string

// List of CXL device types
const (
	CXL_UNKOWN_DEV CxlDevType = "CXLDeviceTypeUnkown"
	CXL_TYPE1_DEV  CxlDevType = "CXLType1Device"
	CXL_TYPE2_DEV  CxlDevType = "CXLType2Device"
	CXL_TYPE3_DEV  CxlDevType = "CXLType3Device"
)

// CxlRev : The revision the CXL device, ie rev 1.1, 2.0, 3.0.
type CxlRev string

// List of CXL revisions
const (
	CXL_REV_UNKOWN CxlRev = "CXL_unkown"
	CXL_REV_1_1    CxlRev = "CXL1.1"
	CXL_REV_2_0    CxlRev = "CXL2.0"
	CXL_REV_3_0    CxlRev = "CXL3.0"
)

// Capability struct for CXL device
type CxlCaps struct {
	Cache_Cap bool
	IO_Cap    bool
	Mem_Cap   bool
	Cache_En  bool
	IO_En     bool
	Mem_En    bool
}

// Memory Attribute table for CXL memory perforrmance
type CxlMemAttr struct {
	ReadLatency    uint16
	WriteLatency   uint16
	ReadBandwidth  uint16
	WriteBandwidth uint16
}

func init() {
	initVendorTable()
	getPciMmConfig()
	ACPITables.FetchCedt()
}

func initVendorTable() {
	PciVendor = make(map[string]string)
	fileScanner := bufio.NewScanner(strings.NewReader(pci_ids))
	fileScanner.Split(bufio.ScanLines)
	for fileScanner.Scan() {
		id, vendor, cut := strings.Cut(fileScanner.Text(), "  ")
		if cut {
			if len(id) == 4 {
				if !strings.HasPrefix(id, "\t") {
					PciVendor[id] = vendor
				}
			}
		}
	}
}

type ACPI struct {
	CEDT []byte
}

// ACPI tables are static, initialize via init() func
var ACPITables = ACPI{}

// Update local copy of the cedt .
func (a *ACPI) FetchCedt() {
	b, err := readACPI("CEDT")
	if err == nil {
		acpiHdr := parseStruct(b, ACPI_HEADER{})
		if string(acpiHdr.Signature[:]) == "CEDT" {
			a.CEDT = b
		}
	} else {
		klog.V(DBG_LVL_BASIC).Info(err)
	}
}

// Get cedt header struct
func (a *ACPI) GetCedtHeader() *ACPI_HEADER {
	acpiHdr := parseStruct(a.CEDT, ACPI_HEADER{})
	return &acpiHdr
}

// Get cedt header struct size in bytes
func (a *ACPI) CedtHeaderSize() int {
	return StructSize(ACPI_HEADER{})
}

// Get subtable cedt struct by offset.
func (a *ACPI) GetCedtSubtable(ofs int) interface{} {
	subT := parseStruct(a.CEDT[ofs:], CEDT_CXL_HOST_BRIDGE{})
	switch cedt_struct_types(subT.Type) {
	case ACPI_CEDT_CXL_HOST_BRIDGE:
		return subT
	case ACPI_CEDT_CXL_FIXED_MEMORY_WINDOW:
		tempT := parseStruct(a.CEDT[ofs:], cedt_cxl_fixed_memory_window_struct{})
		return parseStruct(a.CEDT[ofs:], CEDT_CXL_FIXED_MEMORY_WINDOW(uint(tempT.Record_Length)))
	case ACPI_CEDT_CXL_XOR_INTERLEAVE_MATH:
		tempT := parseStruct(a.CEDT[ofs:], cedt_cxl_xor_interleave_math_struct{})
		return parseStruct(a.CEDT[ofs:], CEDT_CXL_XOR_INTERLEAVE_MATH(uint(tempT.Record_Length)))
	case ACPI_CEDT_RCEC_DOWNSTREAM_PORT_ASSOCIATION_STRCUT:
		return parseStruct(a.CEDT[ofs:], CEDT_RCEC_DOWNSTREAM_PORT_ASSOCIATION_STRCUT{})
	}
	return nil
}

// Get subtable cedt struct size in bytes.
func (a *ACPI) GetCedtSubtableSize(ofs int) int {
	// All sub tables shares the same header so we can use any table to get the size
	subT := parseStruct(a.CEDT[ofs:], CEDT_CXL_HOST_BRIDGE{})
	return int(subT.Record_Length)
}

type CxlDev struct {
	Bdf        *BDF                   `json:"BDF"`
	Vendor     string                 `json:"Vendor"`
	CXLrev     CxlRev                 `json:"CXL-Rev"`
	CXLdevtype CxlDevType             `json:"CXL-Type"`
	PCIE       []byte                 `json:"-"`
	Memdev     *MemoryDeviceRegisters `json:"-"`
	CmpReg     *ComponentRegistersPtr `json:"-"`
}

type ComponentRegistersPtr struct {
	Ras_Cap         *CMPREG_RAS_CAP
	Link_Cap        *CMPREG_LINK_CAP
	HDM_Decoder_Cap *cmpreg_hdm_decoder_cap_struct
}

// initialize the structure based on BDF value
func (c *CxlDev) init(b *BDF) error {
	var err error = nil
	if b == nil {
		err = fmt.Errorf("bdf is empty")
	} else {
		c.Bdf = b
		c.updatePcieConfig()
		c.Vendor = c.GetVendorInfo()
		c.CXLrev = c.GetCxlRev()
		c.CXLdevtype = c.GetCxlType()
		if !c.isCxlRcd() {
			// get info from register locator
			pcieHeader := parseStruct(c.PCIE, PCIE_CONFIG_HDR{})
			regLoc := c.GetDvsec(CXL_DVSEC_REGISTER_LOCATOR).(registerLocator)
			for _, blk := range regLoc.Register_Block {
				bir := blk.Register_Offset_Low.Register_BIR
				baseAddr := int64(pcieHeader.Base_Address_Registers[bir].Base_Address<<4) | int64(blk.Register_Offset_Low.Register_Block_Offset_Low) | int64(blk.Register_Offset_High.Register_Block_Offset_High)<<32

				if blk.Register_Offset_Low.Register_Block_Identifier == 1 { //component registers
					c.parseComReg(baseAddr)
				}
				if blk.Register_Offset_Low.Register_Block_Identifier == 3 { // cxl device registers
					reg := readMemory4k(baseAddr)
					cxlMemDevCap := parseStruct(reg, DEVICE_CAPABILITIES_ARRAY_REGISTER{})
					parsedCxlMemDevCap := parseStruct(reg, CXL_MEMORY_DEVICE_REGISTERS(uint(cxlMemDevCap.Capabilities_Count)))
					c.Memdev = &parsedCxlMemDevCap
				}
			}
		}
	}

	return err
}

// check if a device is CXL memory device.
func (c *CxlDev) isCxlDev() bool {
	pcieHeader := parseStruct(c.PCIE, PCIE_CONFIG_HDR{})
	klog.V(DBG_LVL_DETAIL).InfoS("InfoS structured:   cxl-util: isCXLDev", "Vendor", hex(pcieHeader.Vendor_ID), "device", hex(pcieHeader.Device_ID), "class", hex(pcieHeader.Class_Code.Base_Class_Code), "sub", hex(pcieHeader.Class_Code.Sub_Class_Code), "prog-if", hex(pcieHeader.Class_Code.Prog_if))
	if pcieHeader.Class_Code.Base_Class_Code == 0x5 && // 0x05: Memory Controller
		pcieHeader.Class_Code.Sub_Class_Code == 0x2 && // 0x02: CXL memory devic
		pcieHeader.Class_Code.Prog_if == 0x10 { // 0x10: Always 0x10 per spec
		return true
	}
	return false
}

// check if a device is RCD ( CXL 1.1 device )
func (c *CxlDev) isCxlRcd() bool {
	return c.CXLrev == CXL_REV_1_1
}

// parse component register from address
func (c *CxlDev) parseComReg(addrBase int64) {
	cmpReg := ComponentRegistersPtr{}
	reg := readMemory4k(addrBase + 0x1000)
	comRegCapHdr := parseStruct(reg, COMPONENT_REG_HEADER{})
	for i := uint8(0); i < comRegCapHdr.Array_Size; i++ {
		comRegCapPtr := parseStruct(reg[4*(i+1):], COMPONENT_CAPABILITIES_HEADER{})
		switch cxl_cmp_cap_id(comRegCapPtr.Capability_ID) {
		case CXL_CMPREG_RAS_CAP: //2
			capStruct := parseStruct(reg[comRegCapPtr.Capability_Pointer:], CMPREG_RAS_CAP{})
			cmpReg.Ras_Cap = &capStruct
		case CXL_CMPREG_LINK_CAP: // 4
			capStruct := parseStruct(reg[comRegCapPtr.Capability_Pointer:], CMPREG_LINK_CAP{})
			cmpReg.Link_Cap = &capStruct
		case CXL_CMPREG_HDM_DECODER_CAP: // 5
			hdmDecoderCapHdr := parseStruct(reg[comRegCapPtr.Capability_Pointer:], HDM_DECODER_CAP{})
			capStruct := parseStruct(reg[comRegCapPtr.Capability_Pointer:], CMPREG_HDM_DECODER_CAP(hdmDecoderCapHdr.getDecoderCounts()))
			cmpReg.HDM_Decoder_Cap = &capStruct
		case CXL_CMPREG_NULL, // 0
			CXL_CMPREG_CAP,                      // 1
			CXL_CMPREG_SECURE_CAP,               // 3
			CXL_CMPREG_EXT_SECURE_CAP,           // 6
			CXL_CMPREG_IDE_CAP,                  // 7
			CXL_CMPREG_SNOOP_FLT_CAP,            // 8
			CXL_CMPREG_TIMEOUT_N_ISOLATION_CAP,  // 9
			CXL_CMPREG_CACEHMEM_EXT_CAP,         // A
			CXL_CMPREG_BI_ROUTE_TABLE_CAP,       // B
			CXL_CMPREG_BI_DECODER_CAP,           // C
			CXL_CMPREG_CACHE_ID_ROUTE_TABLE_CAP, // D
			CXL_CMPREG_CACHE_ID_DECODER_CAP,     // E
			CXL_CMPREG_EXT_HDM_DECODER_CAP:      // F
			fmt.Printf("Component Reg [%d] is not supported yet", comRegCapPtr.Capability_ID)
		}
	}
	c.CmpReg = &cmpReg
}

// Update local copy of the pcie config .
func (c *CxlDev) updatePcieConfig() {
	c.PCIE = readMemory4k(c.Bdf.bdfToMemAddr())
}

// return the BDF as string BUS:DEV.FUN
func (c *CxlDev) GetBdfString() string {
	return fmt.Sprintf("%02X:%02X.%1X", c.Bdf.Bus, c.Bdf.Device, c.Bdf.Function)
}

// return a list of DVSEC tables from the CXL device
func (c *CxlDev) GetDvsecList() map[cxl_dvsec_id]uint32 {
	dvsecMap := make(map[cxl_dvsec_id]uint32)
	next_cap := uint32(EXT_DVSEC_OFFSET)
	for next_cap != 0 {
		pcieCapHeader := parseStruct(c.PCIE[next_cap:], PCIE_EXT_CAP_HDR{})
		if int(pcieCapHeader.DVSEC_hdr1.DVSEC_Vendor_ID) == CXL_Vendor_ID {
			dvsec_id := pcieCapHeader.DVSEC_hdr2.DVSEC_ID
			dvsecMap[cxl_dvsec_id(dvsec_id)] = next_cap
		}
		next_cap = uint32(pcieCapHeader.Next_Cap_ofs)
	}
	return dvsecMap
}

// return the struct of a DVSEC
func (c *CxlDev) GetDvsec(dvsecId cxl_dvsec_id) interface{} {
	Dvseclist := c.GetDvsecList()
	Dvsecoffset, ok := Dvseclist[dvsecId]
	if !ok {
		klog.Error("can't find Dvseclist")
	}
	switch dvsecId {
	case CXL_DVSEC_PCIE_DVSEC_FOR_CXL:
		return parseStruct(c.PCIE[Dvsecoffset:], PCIE_DVSEC_FOR_CXL{})
	case CXL_DVSEC_NON_CXL_FUNC_MAP:
		return parseStruct(c.PCIE[Dvsecoffset:], NON_CXL_FUNC_MAP{})
	case CXL_DVSEC_CXL2_0_EXR_DVESC:
		return parseStruct(c.PCIE[Dvsecoffset:], CXL2_0_EXR_DVESC{})
	case CXL_DVSEC_GPF_DVSEC_FOR_PORTS:
		return parseStruct(c.PCIE[Dvsecoffset:], GPF_DVSEC_FOR_PORTS{})
	case CXL_DVSEC_GPF_DVSEC_FOR_DEV:
		return parseStruct(c.PCIE[Dvsecoffset:], GPF_DVSEC_FOR_DEV{})
	case CXL_DVSEC_PCIE_DVSEC_FOR_FLEX_BUS_PORT:
		return parseStruct(c.PCIE[Dvsecoffset:], PCIE_DVSEC_FOR_FLEX_BUS_PORT{})
	case CXL_DVSEC_REGISTER_LOCATOR:
		RegisterLocator := parseStruct(c.PCIE[Dvsecoffset:], registerLocator{})
		BlockNumber := RegisterLocator.getRegisterBlockNumberFromHeader()
		return parseStruct(c.PCIE[Dvsecoffset:], REGISTER_LOCATOR(BlockNumber))
	case CXL_DVSEC_MLD:
		return parseStruct(c.PCIE[Dvsecoffset:], MLD{})
	case CXL_DVSEC_PCIE_DVSEC_FOR_TEST_CAP:
		return parseStruct(c.PCIE[Dvsecoffset:], PCIE_DVSEC_FOR_TEST_CAP{})
	}
	return nil
}

// return the CXL revision
func (c *CxlDev) GetCxlRev() CxlRev {
	Dvseclist := c.GetDvsecList()
	_, ok := Dvseclist[7]
	if !ok {
		return CXL_REV_1_1
	} else {
		CXLdvsec := c.GetDvsec(CXL_DVSEC_PCIE_DVSEC_FOR_FLEX_BUS_PORT).(PCIE_DVSEC_FOR_FLEX_BUS_PORT)
		switch CXLdvsec.PCIE_ext_cap_hdr.DVSEC_hdr1.DVSEC_Rev {
		case 0:
			return CXL_REV_1_1
		case 1:
			return CXL_REV_2_0
		case 2:
			return CXL_REV_3_0
		default:
			return CXL_REV_UNKOWN
		}
	}

}

// return the capacities info of the CXL device
func (c *CxlDev) GetCxlCap() CxlCaps {
	Dvsecforcxl := c.GetDvsec(CXL_DVSEC_PCIE_DVSEC_FOR_CXL).(PCIE_DVSEC_FOR_CXL)
	return CxlCaps{
		Cache_Cap: UintToBool(Dvsecforcxl.CXL_cap.Cache_Cap),
		IO_Cap:    UintToBool(Dvsecforcxl.CXL_cap.IO_Cap),
		Mem_Cap:   UintToBool(Dvsecforcxl.CXL_cap.Mem_Cap),
		Cache_En:  UintToBool(Dvsecforcxl.CXL_ctrl.Cache_En),
		IO_En:     UintToBool(Dvsecforcxl.CXL_ctrl.IO_En),
		Mem_En:    UintToBool(Dvsecforcxl.CXL_ctrl.Mem_En),
	}
}

// convert integer to bool
func UintToBool(i bitfield_1b) bool {
	if i == 1 {
		return true
	} else {
		return false
	}
}

// return the type info of the CXL device ( type 1/ type 2/ type 3 )
// Type 1 - CXL.cache and CXL.io
// Type 2 - CXM.mem and CXL.cache and CXL.io
// Type 3 - CXL.mem and CXL.io
func (c *CxlDev) GetCxlType() CxlDevType {
	CXLCAP := c.GetCxlCap()
	if CXLCAP.Cache_En && CXLCAP.IO_En && !CXLCAP.Mem_En {
		return CXL_TYPE1_DEV
	} else if CXLCAP.Mem_En && CXLCAP.Cache_En && CXLCAP.IO_En {
		return CXL_TYPE2_DEV
	} else if CXLCAP.Mem_En && CXLCAP.IO_En && !CXLCAP.Cache_En {
		return CXL_TYPE3_DEV
	}
	return CXL_UNKOWN_DEV
}

// return the memory size of a CXL device
// Memory_Size_High: Corresponds to bits 63:32 of the CXL Range 1 memory size regardless of whether the device implements CXL HDM Decoder Capability registers.
// Memory_Size_Low: Corresponds to bits 31:28 of the CXL Range 1 memory size regardless of whether the device implements CXL HDM Decoder Capability registers.
func (c *CxlDev) GetMemorySize() int64 {
	dvsecForCxl := c.GetDvsec(CXL_DVSEC_PCIE_DVSEC_FOR_CXL).(PCIE_DVSEC_FOR_CXL)
	return (int64(dvsecForCxl.CXL_range1_size_high.Memory_Size_High) << 32) | (int64(dvsecForCxl.CXL_range1_size_low.Memory_Size_low) << 28)
}

// return the memory base of a CXL device
func (c *CxlDev) GetMemoryBaseAddr() int64 {
	dvsecForCxl := c.GetDvsec(CXL_DVSEC_PCIE_DVSEC_FOR_CXL).(PCIE_DVSEC_FOR_CXL)
	return (int64(dvsecForCxl.CXL_range1_base_high.Memory_Base_High) << 32) | (int64(dvsecForCxl.CXL_range1_base_low.Memory_Base_Low) << 28)
}

// return the pcie header struct
func (c *CxlDev) GetPcieHdr() *PCIE_CONFIG_HDR {
	pcieHeader := parseStruct(c.PCIE, PCIE_CONFIG_HDR{})
	return &pcieHeader
}

// return the Vendor Info of the PCIe/CXL device
func (c *CxlDev) GetVendorInfo() string {
	pcieHeader := parseStruct(c.PCIE, PCIE_CONFIG_HDR{})
	vendor, ok := PciVendor[fmt.Sprintf("%x", pcieHeader.Vendor_ID)]
	if ok {
		return vendor

	} else {
		return "Unkown Vendor"
	}

}

// return the Vendor Info of the PCIe/CXL device
func (c *CxlDev) GetDeviceInfo() string {
	pcieHeader := parseStruct(c.PCIE, PCIE_CONFIG_HDR{})
	return fmt.Sprintf("0x%X", pcieHeader.Device_ID)
}

// parse mem dev register from index
func (c *CxlDev) GetMemDevRegStruct(i int) any {
	if i >= int(c.Memdev.Device_Capabilities_Array_Register.Capabilities_Count) {
		return nil
	}
	hdr := c.Memdev.Device_Capability_Header[i]
	tbl := c.Memdev.GetCapabilityByteArray(i)
	switch hdr.Capability_ID {
	case CXL_MEMDEV_STATUS:
		return parseStruct(tbl, MEMDEV_DEVICE_STATUS{})
	case CXL_MEMDEV_PRIMARY_MAILBOX:
		return parseStruct(tbl, MAILBOX_REGISTERS_CLASS(uint(hdr.Length)))
	case CXL_MEMDEV_MEMDEV_STATUS:
		return parseStruct(tbl, MEMDEV_MEMDEV_STATUS{})
	default:
		return nil
	}
}

// obtain a list of CXL devices on the host
func InitCxlDevList() map[string]*CxlDev {
	CxlDevMap := make(map[string]*CxlDev)

	pcieDevPath := "/sys/bus/pci/devices"
	links, err := os.ReadDir(pcieDevPath)
	if err != nil {
		klog.Fatal(err)
	}
	for _, link := range links {
		// init BDF struct
		bdf := BDF{}
		// Convert the Linux fs format to structure
		bdf.addrToBDF(link.Name())
		klog.V(DBG_LVL_DETAIL).InfoS("cxl-util.InitCxlDevList", "Addr", hex(bdf.bdfToMemAddr()))
		if checkCxlDevClass(link.Name()) {
			new_CxlDev := CxlDev{}
			err = new_CxlDev.init(&bdf)
			if err == nil && new_CxlDev.isCxlDev() {
				klog.V(DBG_LVL_INFO).InfoS("cxl-util.InitCxlDevList Device found", "Link", link.Name())
				CxlDevMap[new_CxlDev.GetBdfString()] = &new_CxlDev
			}
		}

	}
	return CxlDevMap
}

func checkCxlDevClass(link string) bool {
	path := fmt.Sprintf("/sys/bus/pci/devices/%s/class", link)
	fileBytes, err := os.ReadFile(path)
	klog.V(DBG_LVL_DETAIL).InfoS("cxl-util.checkCxlDevClass", "Link", path, "file", fileBytes)
	if fileBytes != nil && err == nil {
		if string(fileBytes) == "0x050210\n" {
			return true
		}
	}

	return false
}

// readMemory4k: return a 4k sized byte array from the memory physical address
func readMemory4k(baseAddress int64) []byte {
	const bufferSize int = 4096

	// Check for 4k boundary align
	klog.V(DBG_LVL_INFO).InfoS("cxl-util.readMemory4k", "BaseAddress", hex(baseAddress))
	if baseAddress&int64(bufferSize-1) != 0 {
		klog.Fatal(fmt.Errorf("BaseAddress is not 4k aligned"))
	}

	file, err := os.Open("/dev/mem")
	if err != nil {
		klog.Fatal(err)
	}
	klog.V(DBG_LVL_DETAIL).Info("cxl-util.readMemory4k /dev/mem is opened")

	defer file.Close()

	mmap, err := syscall.Mmap(int(file.Fd()), baseAddress, bufferSize, syscall.PROT_READ, syscall.MAP_SHARED)
	if err != nil {
		klog.Fatal(err)
	}
	klog.V(DBG_LVL_DETAIL).Info("cxl-util.readMemory4k Mmap is done")

	mmapCp := make([]byte, bufferSize)
	// Save a copy of mmap, which will be elimicated after syscall.Munmap(mmap)
	for offset := 0; offset < bufferSize/4; offset++ {
		// force 32bit read: some systems doesn't support 8bit read in pcie config space
		*(*uint32)(unsafe.Pointer(&mmapCp[4*offset])) = *(*uint32)(unsafe.Pointer(&mmap[4*offset]))
	}

	err = syscall.Munmap(mmap)
	if err != nil {
		klog.Fatal(err)
	}
	klog.V(DBG_LVL_DETAIL).Info("cxl-util.readMemory4k Munmap is done")
	return mmapCp
}

// readACPI: return the byte array of an ACPI table matching the input string
func readACPI(t string) ([]byte, error) {
	var path string = ""
	var err error
	var fileBytes []byte
	// Check for ACPI table name
	if t == "" {
		err = fmt.Errorf("error input: ACPI table name is not supplied")
	} else {
		path = fmt.Sprintf("/sys/firmware/acpi/tables/%s", strings.ToUpper(t))
		fileBytes, err = os.ReadFile(path)
		if err == nil {
			if len(fileBytes) != 0 {
				hdr := parseStruct(fileBytes, ACPI_HEADER{})
				if fmt.Sprintf("%s", hdr.Signature) == t {
					return fileBytes, nil
				} else {
					err = fmt.Errorf("error signature: file signature doesn't match")
				}
			} else {
				err = fmt.Errorf("error read: file read return 0 bytes")
			}
		}
	}
	return nil, err
}

// getPciMmConfig: return the PCI_MMCONFIG value from /proc/iomem
func getPciMmConfig() {
	readFile, err := os.Open("/proc/iomem")
	if err != nil {
		klog.Fatal(err)
	}
	defer readFile.Close()

	fileScanner := bufio.NewScanner(readFile)
	fileScanner.Split(bufio.ScanLines)
	for fileScanner.Scan() {
		text := fileScanner.Text()
		if strings.Contains(text, "MMCONFIG") {
			// String Example "   80000000-8fffffff : PCI MMCONFIG 0000 [bus 00-ff]"
			PCI_MMCONFIG_BASE_ADDR = int64(hexToInt(strings.TrimSpace(strings.Split(fileScanner.Text(), "-")[0])))
			break
		}
	}
}

// parse binary array into struct.
func parseStruct[T any](b []byte, s T) T {
	buf := &bytes.Buffer{}
	buf.Write(b)
	newStruct := s
	err := BitFieldRead(buf, &newStruct)
	if err != nil {
		klog.Fatal(err)
	}
	return newStruct
}

type BDF struct {
	Domain   uint16 `json:"Domain"`
	Bus      uint8  `json:"Bus"`
	Device   uint8  `json:"Device"`
	Function uint8  `json:"Function"`
}

func (b *BDF) addrToBDF(addr string) {
	bdfStringList := strings.Split(strings.ToLower(addr), ":")
	if len(bdfStringList) != 3 {
		klog.Fatal(fmt.Errorf("address format error. Expect $domain:$bus:$dev.$func"))
	}
	dfStringList := strings.Split(bdfStringList[2], ".")
	if len(dfStringList) != 2 {
		klog.Fatal(fmt.Errorf("address format error. Expect $domain:$bus:$dev.$func"))
	}

	b.Domain = uint16(hexToInt(bdfStringList[0]))
	b.Bus = uint8(hexToInt(bdfStringList[1]))
	b.Device = uint8(hexToInt(dfStringList[0]))
	b.Function = uint8(hexToInt(dfStringList[1]))
}

func (b *BDF) bdfToMemAddr() int64 {
	return PCI_MMCONFIG_BASE_ADDR | (int64(b.Function) << 12) | (int64(b.Device) << 15) | (int64(b.Bus) << 20)
}

func hexToInt(hexStr string) uint64 {
	// base 16 for hexadecimal
	result, _ := strconv.ParseUint(hexStr, 16, 64)
	return result
}

// Wrapper function to shorten int to hex convertion call
func hex(a any) string {
	return fmt.Sprintf("%X", a)
}
