// Copyright (c) 2023 Seagate Technology LLC and/or its Affiliates

// This file implements the CXL Mailbox related structures and methods based on CXL spec rev3.0
package cxl

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"os"
	"syscall"
	"time"
	"unsafe"

	"k8s.io/klog/v2"
)

const MB_DOORBELL_CHECK_INTERVAL = 100 // Millisecond
const MB_DOORBELL_TIMEOUT = 5000       // Millisecond

type CXLMailbox struct {
	mailbox      *mailbox_registers
	mmap         []byte   // this holds the entire 4k MMIO area around the mailbox ( because mmap has to be 4k aligned )
	dev_mem_file *os.File // this holds the file pointer to the /dev/mem system file
}

func (mb *CXLMailbox) init(BaseAddr int64, bufSize int) error {
	var err error
	alignedBaseAddr := BaseAddr & 0x7FFFFFFFFFFFF000
	mb.dev_mem_file, err = os.OpenFile("/dev/mem", os.O_RDWR|os.O_SYNC, 0)
	if err != nil {
		klog.Fatal(err)
	}
	if bufSize != 0x1000 { // currently only support 4k size
		bufSize = 0x1000
	}
	klog.V(DBG_LVL_INFO).Infof("cxl-mailbox.init: phyaddr 0x%X size 0x%X", alignedBaseAddr, bufSize)
	mb.mmap, err = syscall.Mmap(int(mb.dev_mem_file.Fd()), alignedBaseAddr, bufSize, syscall.PROT_READ|syscall.PROT_WRITE, syscall.MAP_SHARED)
	if err != nil {
		klog.Fatal(err)
	}

	mb.mailbox = (*mailbox_registers)(unsafe.Pointer(&mb.mmap[BaseAddr&0xFFF]))
	klog.V(DBG_LVL_DETAIL).InfoS("cxl-mailbox.init", "mb.mailbox", mb.mailbox)
	klog.V(DBG_LVL_BASIC).Info("cxl-util.CXLMailbox initialized")
	return err

}

// General mailbox command flow
func (mb *CXLMailbox) Mailbox_cmd(opcode uint16, payload []byte) (uint16, []byte) {
	var RC uint16
	var PL []byte
	//1. Caller reads MB Control Register to verify doorbell is clear
	if mb.mailbox_read_doorbell() {
		fmt.Print("Mailbox is busy. Try again later.")
		return 0xFFFF, nil // door bell is not ready
	}

	//2. Caller writes Command Register
	mb.mailbox_write_cmd_regs(opcode)

	//3. Caller writes Command Payload Registers if input payload is non-empty
	if payload != nil {
		mb.mailbox_write_cmd_payload(payload)
	} else {
		mb.mailbox_clear_payload_length()
	}

	//4. Caller writes MB Control Register to set doorbell
	mb.mailbox_set_doorbell()
	klog.V(DBG_LVL_DETAIL).InfoS("cxl-mailbox.Mailbox_cmd", "MAILBOX OUT", mb.mailbox.print())

	//5. Caller either polls for doorbell to be clear or waits for interrupt if configured
	if !mb.mailbox_check_doorbell() {
		return 0xFFFF, nil // doorbell has not cleared after timeout
	}

	//6. Caller reads MB Status Register to fetch Return code
	RC = mb.mailbox_read_status()

	//7. If command successful, Caller reads Command Register to get Payload Length
	if RC == 0 {
		PL_length := mb.mailbox_read_payload_length()
		//8. If output payload is non-empty, host reads Command Payload Registers
		if PL_length != 0 {
			PL = mb.mailbox_read_payload(PL_length)
		}
	}

	klog.V(DBG_LVL_DETAIL).InfoS("cxl-mailbox.Mailbox_cmd", "MAILBOX IN", mb.mailbox.print())
	return RC, PL
}

func (mb *CXLMailbox) mailbox_read_doorbell() bool {
	return MAILBOX_CONTROL_REGISTER_DOORBELL.read(mb.mailbox.MB_Control) != 0
}
func (mb *CXLMailbox) mailbox_write_cmd_regs(opcode uint16) {
	MAILBOX_COMMAND_REGISTER_COMMAND_OPCODE.write(&mb.mailbox.Command_Register, uint64(opcode))
}
func (mb *CXLMailbox) mailbox_write_cmd_payload(payload []byte) {
	for i, pl := range bytetoU32(payload) {
		mb.mailbox.Commmand_Payload_Registers[i] = pl
	}
	MAILBOX_COMMAND_REGISTER_PAYLOAD_LENGTH.write(&mb.mailbox.Command_Register, uint64(len(payload)))
}
func (mb *CXLMailbox) mailbox_check_doorbell() bool {
	check_count := 0
	time.Sleep(time.Duration(MB_DOORBELL_CHECK_INTERVAL) * time.Millisecond)
	for mb.mailbox_read_doorbell() {
		check_count += 1
		if check_count*MB_DOORBELL_CHECK_INTERVAL >= MB_DOORBELL_TIMEOUT {
			return false
		}
		time.Sleep(time.Duration(MB_DOORBELL_CHECK_INTERVAL) * time.Millisecond)
	}
	return true
}
func (mb *CXLMailbox) mailbox_set_doorbell() {
	MAILBOX_CONTROL_REGISTER_DOORBELL.write(&mb.mailbox.MB_Control, 1)
}
func (mb *CXLMailbox) mailbox_read_status() uint16 {
	return uint16(MAILBOX_STATUS_REGISTER_RETURN_CODE.read(mb.mailbox.MB_Status))
}
func (mb *CXLMailbox) mailbox_read_payload_length() int {
	return int(MAILBOX_COMMAND_REGISTER_PAYLOAD_LENGTH.read(mb.mailbox.Command_Register))
}
func (mb *CXLMailbox) mailbox_read_payload(PL_length int) []byte {
	wholePL := u32toByte(mb.mailbox.Commmand_Payload_Registers[:])
	return wholePL[:PL_length]
}
func (mb *CXLMailbox) mailbox_clear_payload_length() {
	MAILBOX_COMMAND_REGISTER_PAYLOAD_LENGTH.write(&mb.mailbox.Command_Register, 0)
}

// //////////////////////////////////////// Mailbox command for each Opcode
func (mb *CXLMailbox) Mailbox_cmd_get_event_records(event uint8) *get_event_records_output {
	if event > 3 {
		fmt.Print("Invalid event")
		return nil
	}

	payload_reg := []byte{event}
	RC, PL := mb.Mailbox_cmd(0x0100, payload_reg)
	if RC == 0 {
		tmpEventRecord := parseStruct(PL, get_event_records_output{}) // table size various
		EventRecord := parseStruct(PL, GET_EVENT_RECORDS_OUTPUT(uint(tmpEventRecord.Event_Record_Count)))
		return &EventRecord
	} else {
		fmt.Printf("Mailbox ERROR: %Xh  %s", RC, MB_ReturnCode[RC])
		return nil
	}
}

func (mb *CXLMailbox) Mailbox_cmd_clear_event_records(event uint8) uint16 {
	if event > 3 {
		fmt.Print("Invalid event")
		return 0xFFFF
	}

	payload_reg := clear_event_records_output{}
	payload_reg.Event_Log = event
	payload_reg.Clear_Event_Flags = 1
	payload_reg.Number_of_Event_Record_Handles = 0 ////// clear all events

	RC, _ := mb.Mailbox_cmd(0x0101, structtoByte(payload_reg))
	if RC != 0 {
		fmt.Printf("Mailbox ERROR: %Xh  %s", RC, MB_ReturnCode[RC])
	}
	return RC
}

func (mb *CXLMailbox) Mailbox_cmd_get_event_interrupt_policy() *GET_EVENT_INTERRUPT_POLICY_OUTPUT {
	RC, PL := mb.Mailbox_cmd(0x0102, nil)
	if RC == 0 {
		EIP := parseStruct(PL, GET_EVENT_INTERRUPT_POLICY_OUTPUT{})
		return &EIP
	} else {
		fmt.Printf("Mailbox ERROR: %Xh  %s", RC, MB_ReturnCode[RC])
		return nil
	}
}

func (mb *CXLMailbox) Mailbox_cmd_set_event_interrupt_policy(setting []int) uint16 {

	payload_reg := SET_EVENT_INTERRUPT_POLICY_INPUT{}
	payload_reg.Informational_Event_Log_Interrupt_Settings.Interrupt_Mode = bitfield_2b(setting[0])
	payload_reg.Warning_Event_Log_Interrupt_Settings.Interrupt_Mode = bitfield_2b(setting[1])
	payload_reg.Failure_Event_Log_Interrupt_Settings.Interrupt_Mode = bitfield_2b(setting[2])
	payload_reg.Fatal_Event_Log_Interrupt_Settings.Interrupt_Mode = bitfield_2b(setting[3])

	RC, _ := mb.Mailbox_cmd(0x0103, payload_reg.toByteArray())
	if RC != 0 {
		fmt.Printf("Mailbox ERROR: %Xh  %s", RC, MB_ReturnCode[RC])
	}
	return RC
}

func (mb *CXLMailbox) Mailbox_cmd_get_fw_info() *GET_FW_INFO_OUTPUT {
	RC, PL := mb.Mailbox_cmd(0x0200, nil)
	if RC == 0 {
		FW_info := parseStruct(PL, GET_FW_INFO_OUTPUT{})
		return &FW_info
	} else {
		fmt.Printf("Mailbox ERROR: %Xh  %s", RC, MB_ReturnCode[RC])
		return nil
	}
}

func (mb *CXLMailbox) mailbox_cmd_transfer_fw(fw_path string) error {
	fileBytes, err := os.ReadFile(fw_path)
	if err != nil {
		return fmt.Errorf("file read error!")
	}
	if len(fileBytes)%CXL_FW_PACK_SIZE != 0 {
		return fmt.Errorf("fw file must be %d Bytes aligned!", CXL_FW_PACK_SIZE)
	}

	pack_offset := 0
	max_fw_transfer_size := int(MAILBOX_CAPABILITIES_REGISTER_PAYLOAD_SIZE.read(mb.mailbox.MB_Capabilities)) - CXL_FW_PACK_SIZE
	N_transfer := len(fileBytes) / max_fw_transfer_size // Line below: round up operation
	if len(fileBytes)/max_fw_transfer_size != 0 {
		N_transfer++
	}

	for transfer := 0; transfer < N_transfer; transfer++ {
		transfer_size := max_fw_transfer_size
		if len(fileBytes[pack_offset*CXL_FW_PACK_SIZE:]) < max_fw_transfer_size {
			transfer_size = len(fileBytes[pack_offset*CXL_FW_PACK_SIZE:])
		}
		payload_reg := TRASFER_FW_INPUT(uint(transfer_size))
		if N_transfer == 1 {
			payload_reg.Action = 0 // full FW transfer
		} else if transfer == 0 {
			payload_reg.Action = 1 // initial FW transfer
		} else if transfer == N_transfer-1 {
			payload_reg.Action = 3 // end FW transfer
		} else {
			payload_reg.Action = 2 // continue FW transfer
		}
		payload_reg.Offset = uint32(pack_offset)
		payload_reg.Slot = 0
		pack_offset += max_fw_transfer_size / CXL_FW_PACK_SIZE
		RC, _ := mb.Mailbox_cmd(0x0201, structtoByte(payload_reg))
		if RC != 0 {
			return fmt.Errorf("Mailbox ERROR: %Xh  %s", RC, MB_ReturnCode[RC])
		}
	}
	return nil
}

func (mb *CXLMailbox) Mailbox_cmd_get_supported_logs() *get_supported_logs_output {
	RC, PL := mb.Mailbox_cmd(0x0400, nil)
	if RC == 0 {
		SL := parseStruct(PL, GET_SUPPORTED_LOGS_OUTPUT(0)) // variable size
		SL = parseStruct(PL, GET_SUPPORTED_LOGS_OUTPUT(uint(SL.Number_of_Suppoorted_Log_Entries)))
		return &SL
	} else {
		fmt.Printf("Mailbox ERROR: %Xh  %s", RC, MB_ReturnCode[RC])
		return nil
	}
}

func (mb *CXLMailbox) Mailbox_cmd_get_log(log_input [16]byte, offset uint32, length uint32) *get_log_output {
	payload_reg := GET_LOG_INPUT{}
	payload_reg.Log_Identifier = log_input
	payload_reg.Offset = offset
	payload_reg.Length = length

	RC, PL := mb.Mailbox_cmd(0x0401, structtoByte(payload_reg))
	if RC == 0 {
		LOG := parseStruct(PL, GET_LOG_OUTPUT(uint(payload_reg.Length))) // variable size
		return &LOG
	} else {
		fmt.Printf("Mailbox ERROR: %Xh  %s", RC, MB_ReturnCode[RC])
		return nil
	}
}

func (mb *CXLMailbox) Mailbox_cmd_identify_memory_device() *IDENTIFY_MEMORY_DEVICE_OUTPUT {

	RC, PL := mb.Mailbox_cmd(0x4000, nil)
	if RC == 0 {
		device_info := parseStruct(PL, IDENTIFY_MEMORY_DEVICE_OUTPUT{}) // variable size
		return &device_info
	} else {
		fmt.Printf("Mailbox ERROR: %Xh  %s", RC, MB_ReturnCode[RC])
		return nil
	}
}

// OPCODE translate
func (mb *CXLMailbox) SendMailboxCCIbyOPCODE(opcode uint64, args ...interface{}) interface{} {
	switch opcode {

	//CXL device command Opcodes
	//0x0001:"identify",
	//0x0002:"background_operation_status",
	//0x0003:"get_response_message_limit",
	//0x0004:"set_response_message_limit",
	case 0x0100:
		return mb.Mailbox_cmd_get_event_records(args[0].(uint8))
	case 0x0101:
		return mb.Mailbox_cmd_clear_event_records(args[0].(uint8))
	case 0x0102:
		return mb.Mailbox_cmd_get_event_interrupt_policy()
	case 0x0103:
		return mb.Mailbox_cmd_set_event_interrupt_policy(args[0].([]int))
	case 0x0200:
		return mb.Mailbox_cmd_get_fw_info()
	case 0x0201:
		return mb.mailbox_cmd_transfer_fw(args[0].(string))
		//0x0202:"activate_fw",
		//0x0300:"get_timestamp",
		//0x0301:"set_timestamp",
	case 0x0400:
		return mb.Mailbox_cmd_get_supported_logs()
	case 0x0401:
		return mb.Mailbox_cmd_get_log(args[0].([16]byte), args[1].(uint32), args[2].(uint32))

		//CXL memory device command Opcodes
	case 0x4000:
		return mb.Mailbox_cmd_identify_memory_device()
		//0x4100:"get_partition_info",
		//0x4101:"set_partition_info",
		//0x4102:"get_lsa",
		//0x4103:"set_lsa",
		//0x4200:"get_health_info",
		//0x4201:"get_alert_configuration",
		//0x4202:"set_alert_configuration",
		//0x4203:"get_shutdown_state",
		//0x4204:"set_shutdown_state",
		//0x4300:"get_poison_list",
		//0x4301:"inject_poison",
		//0x4302:"clear_poison",
		//0x4303:"get_scan_media_capabilities",
		//0x4304:"scan_media",
		//0x4305:"get_scan_media_results",
		//0x4400:"sanitize",
		//0x4401:"secure_erase",
		//0x4500:"get_security_state",
		//0x4501:"set_passphrase",
		//0x4502:"disable_passphrase",
		//0x4503:"unlock",
		//0x4504:"freeze_security_state",
		//0x4505:"passphrase_secure_erase",
		//0x4600:"security_send",
		//0x4601:"security_receive",
		//0x4700:"get_sld_qos_control",
		//0x4701:"set_sld_qos_control",
		//0x4702:"get_sld_qos_status",

		//CXL FM API Command Opcodes
		//0x5000:"event_notification",
		//0x5100:"identify_switch_device",
		//0x5101:"get_physical_port_state",
		//0x5102:"physical_port_control",
		//0x5103:"send_ppb_cxl_io_configuration_request",
		//0x5200:"get_cirtual_cxl_switch_info",
		//0x5201:"bind_vppb",
		//0x5202:"unbind_vppb",
		//0x5203:"generate_aer_event",
		//0x5300:"tunnel_management_coommand",
		//0x5301:"send_ppb_cxl_io_configuration_request",
		//0x5302:"send_ppb_cxl_io_memory_request",
		//0x5400:"get_ld_info",
		//0x5401:"get_ld_allocations",
		//0x5402:"set_ld_allocations",
		//0x5403:"get_qos_control",
		//0x5404:"set_qos_control",
		//0x5405:"get_qos_status",
		//0x5406:"get_qos_allocated_bw",
		//0x5407:"set_qos_allocated_bw",
		//0x5408:"get_qos_bw_limit",
		//0x5409:"set_qos_bw_limit",
	default:
		return nil
	}

}

func print_struct_table(table any) {
	s, _ := json.MarshalIndent(table, "   ", "   ")
	fmt.Print(string(s), "\n")
}

// define for CXL Mailbox struct
func u32toByte(in []uint32) []byte {
	buf := &bytes.Buffer{}
	binary.Write(buf, binary.LittleEndian, in)
	return buf.Bytes()
}

func bytetoU32(in []byte) []uint32 {
	buf := bytes.NewBuffer(in)
	out := []uint32{}
	binary.Read(buf, binary.LittleEndian, &out)
	return out
}

func structtoByte(s any) []byte {
	buf := &bytes.Buffer{}
	binary.Write(buf, binary.LittleEndian, s)
	return buf.Bytes()
}

func structtoU32(s any) []uint32 {
	return bytetoU32(structtoByte(s))
}

type u32field struct {
	offset   int
	bitwidth int
}

func (u *u32field) mask() uint32 {
	return (1<<u.bitwidth - 1) << u.offset
}

func (u *u32field) read(reg uint32) uint32 {
	return (reg >> u.offset) & (1<<u.bitwidth - 1)
}

func (u *u32field) write(reg *uint32, val uint32) {
	*reg = (*reg &^ u.mask()) | ((val << u.offset) & u.mask())
}

type u64field struct {
	offset   int
	bitwidth int
}

func (u *u64field) mask() uint64 {
	return (1<<u.bitwidth - 1) << u.offset
}

func (u *u64field) read(reg uint64) uint64 {
	return (reg >> u.offset) & (1<<u.bitwidth - 1)
}

func (u *u64field) write(reg *uint64, val uint64) {
	*reg = (*reg &^ u.mask()) | ((val << u.offset) & u.mask())
}

var (
	MAILBOX_CAPABILITIES_REGISTER_PAYLOAD_SIZE                                  = u32field{offset: 0, bitwidth: 5}
	MAILBOX_CAPABILITIES_REGISTER_MB_DOORBELL_INTERRUPT_CAPABLE                 = u32field{offset: 5, bitwidth: 1}
	MAILBOX_CAPABILITIES_REGISTER_BACKGROUND_COMMAND_COMPLETE_INTERRUPT_CAPABLE = u32field{offset: 6, bitwidth: 1}
	MAILBOX_CAPABILITIES_REGISTER_INTERRUPT_MESSAGE_NUMBER                      = u32field{offset: 7, bitwidth: 4}
	MAILBOX_CAPABILITIES_REGISTER_MAILBOX_READY_TIME                            = u32field{offset: 11, bitwidth: 8}
	MAILBOX_CAPABILITIES_REGISTER_TYPE                                          = u32field{offset: 19, bitwidth: 4}

	MAILBOX_CONTROL_REGISTER_DOORBELL                              = u32field{offset: 0, bitwidth: 1}
	MAILBOX_CONTROL_REGISTER_DOORBELL_INTERRUPT                    = u32field{offset: 1, bitwidth: 1}
	MAILBOX_CONTROL_REGISTER_BACKGROUND_COMMAND_COMPLETE_INTERRUPT = u32field{offset: 2, bitwidth: 1}

	MAILBOX_COMMAND_REGISTER_COMMAND_OPCODE = u64field{offset: 0, bitwidth: 16}
	MAILBOX_COMMAND_REGISTER_PAYLOAD_LENGTH = u64field{offset: 16, bitwidth: 21}

	MAILBOX_STATUS_REGISTER_BACKGROUND_OPERATION            = u64field{offset: 0, bitwidth: 1}
	MAILBOX_STATUS_REGISTER_RETURN_CODE                     = u64field{offset: 32, bitwidth: 16}
	MAILBOX_STATUS_REGISTER_VENDOR_SPECIFIC_EXTENDED_STATUS = u64field{offset: 48, bitwidth: 16}

	BACKGROUND_COMMAND_STATUS_REGISTER_COMMAND_OPCODE                  = u64field{offset: 0, bitwidth: 16}
	BACKGROUND_COMMAND_STATUS_REGISTER_PERCENTAGE_COMPLETE             = u64field{offset: 16, bitwidth: 7}
	BACKGROUND_COMMAND_STATUS_REGISTER_RETURN_CODE                     = u64field{offset: 32, bitwidth: 16}
	BACKGROUND_COMMAND_STATUS_REGISTER_VENDOR_SPECIFIC_EXTENDED_STATUS = u64field{offset: 48, bitwidth: 16}
)

type mailbox_registers struct {
	MB_Capabilities                    uint32
	MB_Control                         uint32
	Command_Register                   uint64
	MB_Status                          uint64
	Background_Command_Status_Register uint64
	Commmand_Payload_Registers         [512]uint32 // MMIO operations require array not slice. Allocate 512*4 Bytes for now.
}

func (mb *mailbox_registers) print() string {
	printStr := "cxl-mailbox print:\n"
	s, _ := json.MarshalIndent(parseStruct(structtoByte(mb.MB_Capabilities), MAILBOX_CAPABILITIES_REGISTER{}), "   ", "   ")
	printStr += "MAILBOX_CAPABILITIES_REGISTER\n" + string(s)
	s, _ = json.MarshalIndent(parseStruct(structtoByte(mb.MB_Control), MAILBOX_CONTROL_REGISTER{}), "   ", "   ")
	printStr += "MAILBOX_CONTROL_REGISTER\n" + string(s)
	s, _ = json.MarshalIndent(parseStruct(structtoByte(mb.Command_Register), COMMAND_REGISTER{}), "   ", "   ")
	printStr += "COMMAND_REGISTER\n" + string(s)
	s, _ = json.MarshalIndent(parseStruct(structtoByte(mb.MB_Status), MAILBOX_STATUS_REGISTER{}), "   ", "   ")
	printStr += "MAILBOX_STATUS_REGISTER\n" + string(s)
	s, _ = json.MarshalIndent(parseStruct(structtoByte(mb.Background_Command_Status_Register), BACKGROUND_COMMAND_STATUS_REGISTER{}), "   ", "   ")
	printStr += "BACKGROUND_COMMAND_STATUS_REGISTER\n" + string(s)
	s, _ = json.MarshalIndent(parseStruct(structtoByte(mb.MB_Control), MAILBOX_CONTROL_REGISTER{}), "   ", "   ")
	printStr += "COMMMAND_PAYLOAD_REGISTERS\n"
	for _, val := range mb.Commmand_Payload_Registers {
		printStr += fmt.Sprintf("0x%X\t", val)
	}
	return printStr
}

type MAILBOX_CAPABILITIES_REGISTER struct {
	Payload_Size                                  bitfield_5b
	MB_Doorbell_Interrupt_Capable                 bitfield_1b
	Background_Command_Complete_Interrupt_Capable bitfield_1b
	Interrupt_Message_Number                      bitfield_4b
	Reserved                                      bitfield_21b
}

type MAILBOX_CONTROL_REGISTER struct {
	Doorbell                              bitfield_1b
	MB_Doorbell_Interrupt                 bitfield_1b
	Background_Command_Complete_Interrupt bitfield_1b
	Reserved                              bitfield_29b
}

type COMMAND_REGISTER struct {
	Command_Opcode bitfield_16b
	Payload_Length bitfield_21b
	Reserved       bitfield_27b
}

type MAILBOX_STATUS_REGISTER struct {
	Background_Operation            bitfield_1b
	Reserved                        bitfield_31b
	Return_Code                     bitfield_16b
	Vendor_Specific_Extended_Status bitfield_16b
}

type BACKGROUND_COMMAND_STATUS_REGISTER struct {
	Command_Opcode                  bitfield_16b
	Percentage_Complete             bitfield_7b
	Reserved                        bitfield_9b
	Return_Code                     bitfield_16b
	Vendor_Specific_Extended_Status bitfield_16b
}

// Mailbox return codes
var MB_ReturnCode = [23]string{
	"Success",                                //00h
	"Background Command Started",             //01h
	"Invalid Input",                          //02h
	"Unsupported",                            //03h
	"Internal Error",                         //04h
	"Retry Required",                         //05h
	"Busy",                                   //06h
	"Media Disabled",                         //07h
	"FW Transfer in Progress",                //08h
	"FW Transfer Out of Order",               //09h
	"FW Authentication Failed",               //0Ah
	"Invalid Slot",                           //0Bh
	"Activation Failed, FW Rolled Back",      //0Ch
	"Activation Failed, Cold Reset Required", //0Dh
	"Invalid Handle",                         //0Eh
	"Invalid Physical Address",               //0Fh
	"Inject Poison Limit Reached",            //10h
	"Permanent Media Failure",                //11h
	"Aborted",                                //12h
	"Invalid Security State",                 //13h
	"Incorrect Passphrase",                   //14h
	"Unsupported Mailbox",                    //15h
	"Invalid Payload Length",                 //16h
}

// Mailbox Payload Structures
type get_event_records_output struct {
	Flags                          uint8
	Reserved                       uint8
	Overflow_Error_Count           uint16
	First_Overflow_Event_Timestamp uint64
	Last_Overflow_Event_Timestamp  uint64
	Event_Record_Count             uint16
	Reserved2                      [10]uint8 //0xA
	Event_Records                  []uint64
}

func GET_EVENT_RECORDS_OUTPUT(Record_Count uint) get_event_records_output {
	slice := make([]uint64, Record_Count)
	return get_event_records_output{
		Event_Records: slice,
	}
}

type clear_event_records_output struct {
	Event_Log                      uint8
	Clear_Event_Flags              uint8
	Number_of_Event_Record_Handles uint16
	Reserved                       uint64
	Event_Record_Handles           []uint64
}

func CLEAR_EVENT_RECORDS_INPUT(Record_Count uint) clear_event_records_output {
	slice := make([]uint64, Record_Count)
	return clear_event_records_output{
		Event_Record_Handles: slice,
	}
}

type INTERRUPT_SETTINGS struct {
	Interrupt_Mode           bitfield_2b
	Reserved                 bitfield_2b
	Interrupt_Message_Number bitfield_4b
}

func (i *INTERRUPT_SETTINGS) toByte() byte {
	return uint8(i.Interrupt_Mode) | (uint8(i.Interrupt_Message_Number) << 4)
}

type GET_EVENT_INTERRUPT_POLICY_OUTPUT struct {
	Informational_Event_Log_Interrupt_Settings INTERRUPT_SETTINGS
	Warning_Event_Log_Interrupt_Settings       INTERRUPT_SETTINGS
	Failure_Event_Log_Interrupt_Settings       INTERRUPT_SETTINGS
	Fatal_Event_Log_Interrupt_Settings         INTERRUPT_SETTINGS
}

type SET_EVENT_INTERRUPT_POLICY_INPUT struct {
	Informational_Event_Log_Interrupt_Settings INTERRUPT_SETTINGS
	Warning_Event_Log_Interrupt_Settings       INTERRUPT_SETTINGS
	Failure_Event_Log_Interrupt_Settings       INTERRUPT_SETTINGS
	Fatal_Event_Log_Interrupt_Settings         INTERRUPT_SETTINGS
}

func (s *SET_EVENT_INTERRUPT_POLICY_INPUT) toByteArray() []byte {
	return []byte{s.Informational_Event_Log_Interrupt_Settings.toByte(),
		s.Warning_Event_Log_Interrupt_Settings.toByte(),
		s.Failure_Event_Log_Interrupt_Settings.toByte(),
		s.Fatal_Event_Log_Interrupt_Settings.toByte()}
}

type SLOT_FW_REVISION struct {
	FW_Revision [16]byte
}

type GET_FW_INFO_OUTPUT struct {
	FW_Slots_Supported         uint8
	FW_Slot_Info               uint8
	FW_Activation_Capabilities uint8
	Reserved                   [13]uint8
	Slot_FW                    [4]SLOT_FW_REVISION
}

var CXL_FW_PACK_SIZE = 128

type trasfer_fw_input struct {
	Action    uint8
	Slot      uint8
	Reserved  uint16
	Offset    uint32
	Reserved2 [120]uint8 //0x78
	Data      []uint8
}

func TRASFER_FW_INPUT(transfer_size uint) trasfer_fw_input {
	slice := make([]uint8, transfer_size)
	return trasfer_fw_input{
		Data: slice,
	}
}

type SUPPORTED_LOG_ENTRY struct {
	Log_Identifier [16]byte //0x10
	Log_Size       uint32
}

type get_supported_logs_output struct {
	Number_of_Suppoorted_Log_Entries uint16
	Reserved                         [6]uint8
	Supported_Log_Entries            []SUPPORTED_LOG_ENTRY
}

func GET_SUPPORTED_LOGS_OUTPUT(Entries uint) get_supported_logs_output {
	slice := make([]SUPPORTED_LOG_ENTRY, Entries)
	return get_supported_logs_output{
		Supported_Log_Entries: slice,
	}
}

type GET_LOG_INPUT struct {
	Log_Identifier [16]byte //0x10
	Offset         uint32
	Length         uint32
}

type get_log_output struct {
	Log_Data []byte
}

func GET_LOG_OUTPUT(Length uint) get_log_output {
	slice := make([]byte, Length)
	return get_log_output{
		Log_Data: slice,
	}
}

type IDENTIFY_MEMORY_DEVICE_OUTPUT struct {
	FW_Revision                             [16]byte //0x10
	Total_Capaciity                         uint64
	Volatile_Only_Capacity                  uint64
	Persistent_Only_Capacitgy               uint64
	Partition_Aliggnment                    uint64
	Informational_Event_Log_Size            uint16
	Warning_Event_Log_Size                  uint16
	Failure_Event_Log_Size                  uint16
	Fatal_Event_Log_Size                    uint16
	LSA_Size                                uint32
	Poison_List_Maximum_Media_Error_Records [3]uint8
	Inject_Poison_Limit                     uint16
	Poison_Handling_Capabilities            uint8
	Qos_Telemetry_Capabilities              uint8
}
