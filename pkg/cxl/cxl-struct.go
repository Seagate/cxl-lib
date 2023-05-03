// Copyright (c) 2023 Seagate Technology LLC and/or its Affiliates

// This file implements the CXL related structures based on CXL spec rev1.1 with some updates from spec rev2.0
package cxl

const CXL_Vendor_ID = 0x1E98
const EXT_DVSEC_OFFSET = 0x100

// define for Advanced Configuration and Power Interface (ACPI) header
type ACPI_HEADER struct {
	Signature             [4]byte
	Table_Length          uint32
	Revision              uint8
	Checksum              byte
	Oem_ID                [6]byte
	Oem_Table_ID          [8]byte
	Oem_Revision          uint32
	Asl_Compiler_ID       [4]byte
	Asl_Compiler_Revision uint32
}

func (a *ACPI_HEADER) getCedtSubtableCountFromAcpiHeader() int {
	// ACPI_HEADER is at fixed size 36B
	// Each CEDT_SUBTABLE is at fixed size 32B
	return (int(a.Table_Length) - 36) / 32
}

// // CXL Early Discovery Table (CEDT)
type CEDT_SUBTABLE struct {
	Subtable_Type          byte
	Reserved               byte
	Length                 uint16
	Associated_host_bridge uint32
	Specification_version  uint32
	Reserved2              uint32
	Register_base          uint64
	Register_length        uint64
}

type cedt_table_struct struct {
	Header   ACPI_HEADER
	Subtable []CEDT_SUBTABLE
}

func CEDT_TABLE(size uint) cedt_table_struct {
	slice := make([]CEDT_SUBTABLE, size)
	return cedt_table_struct{
		Subtable: slice,
	}
}

// define for PCIE config space struct
type PCIE_CLASS_CODE struct {
	Prog_if         uint8
	Sub_Class_Code  uint8
	Base_Class_Code uint8
}

type BAR struct {
	Region_Type  bitfield_1b
	Locatable    bitfield_2b
	Prefetchable bitfield_1b
	Base_Address bitfield_28b
}

type PCIE_CONFIG_HDR struct {
	Vendor_ID              uint16
	Device_ID              uint16
	Command                uint16
	Status                 int16
	Rev_ID                 uint8
	Class_Code             PCIE_CLASS_CODE
	Misc                   uint32
	Base_Address_Registers [6]BAR
	Misc2                  [6]int32
}

// Designated Vendor-Specific Extended Capability (DVSEC)
type DVSEC_HDR1 struct {
	DVSEC_Vendor_ID bitfield_16b
	DVSEC_Rev       bitfield_4b
	DVSEC_Length    bitfield_12b
}

type DVSEC_HDR2 struct {
	DVSEC_ID uint16
}

type PCIE_EXT_CAP_HDR struct {
	PCIE_ext_cap_ID bitfield_16b
	Cap_Ver         bitfield_4b
	Next_Cap_ofs    bitfield_12b
	DVSEC_hdr1      DVSEC_HDR1
	DVSEC_hdr2      DVSEC_HDR2
}

type PCIE_DVSEC_FOR_CXL struct {
	PCIE_ext_cap_hdr     PCIE_EXT_CAP_HDR
	CXL_cap              CXL_CAP
	CXL_ctrl             CXL_CTRL
	CXL_stat             CXL_STAT
	CXL_ctrl2            CXL_CTRL2
	CXL_stat2            CXL_STAT2
	CXL_lock             CXL_LOCK
	CXL_cap2             CXL_CAP2
	CXL_range1_size_high CXL_RANGE_SIZE_HIGH
	CXL_range1_size_low  CXL_RANGE_SIZE_LOW
	CXL_range1_base_high CXL_RANGE_BASE_HIGH
	CXL_range1_base_low  CXL_RANGE_BASE_LOW
	CXL_range2_size_high CXL_RANGE_SIZE_HIGH
	CXL_range2_size_low  CXL_RANGE_SIZE_LOW
	CXL_range2_base_high CXL_RANGE_BASE_HIGH
	CXL_range2_base_low  CXL_RANGE_BASE_LOW
}
type CXL_CAP struct {
	Cache_Cap               bitfield_1b
	IO_Cap                  bitfield_1b
	Mem_Cap                 bitfield_1b
	Mem_HwInit_Mode         bitfield_1b
	HDM_Count               bitfield_2b
	Cache_Writeback         bitfield_1b
	CXL_reset_Cap           bitfield_1b
	CXL_reset_timeout       bitfield_3b
	CXL_reset_mem_clr_cap   bitfield_1b
	RsvdP                   bitfield_1b
	Multiple_Logical_Device bitfield_1b
	Viral_Cap               bitfield_1b
	PM_Init_comp            bitfield_1b
}

type CXL_CTRL struct {
	Cache_En             bitfield_1b
	IO_En                bitfield_1b
	Mem_En               bitfield_1b
	Cache_SF_Coverage    bitfield_5b
	Cache_SF_Granularity bitfield_3b
	Cache_Clean_Eviction bitfield_1b
	RsvdP                bitfield_2b
	Viral_En             bitfield_1b
	RsvdP2               bitfield_1b
}

type CXL_STAT struct {
	RsvdP      bitfield_14b
	Viral_Stat bitfield_1b
	RsvdP2     bitfield_1b
}

type CXL_CTRL2 struct {
	Disable_Caching      bitfield_1b
	Init_Cache_WriteBack bitfield_1b
	Init_CXL_Rest        bitfield_1b
	CXL_Reset_Mem_Clr_En bitfield_1b
	RsvdP                bitfield_12b
}

type CXL_STAT2 struct {
	Cache_Invalid     bitfield_1b
	CXL_Rest_Complete bitfield_1b
	CXL_Reset_Error   bitfield_1b
	RsvdP             bitfield_12b
	PM_Init_Complete  bitfield_1b
}

type CXL_LOCK struct {
	CONFIG_LOCK bitfield_1b
	RsvdP       bitfield_15b
}

type CXL_CAP2 struct {
	Cache_Size_Unit bitfield_4b
	RsvdP           bitfield_4b
	Cache_Size      bitfield_8b
}

type CXL_RANGE_SIZE_HIGH struct {
	Memory_Size_High uint32
}

type CXL_RANGE_SIZE_LOW struct {
	Memory_info_Valid     bitfield_1b
	Memory_Active         bitfield_1b
	Media_Type            bitfield_3b
	Memory_Class          bitfield_3b
	Desired_Interleave    bitfield_5b
	Memory_Active_Timeout bitfield_3b
	RsvdP                 bitfield_12b
	Memory_Size_low       bitfield_4b
}

type CXL_RANGE_BASE_HIGH struct {
	Memory_Base_High uint32
}

type CXL_RANGE_BASE_LOW struct {
	RsvdP           bitfield_28b
	Memory_Base_Low bitfield_4b
}

// NON_CXL_FUNC_MAP
type NON_CXL_FUNC_MAP struct {
	PCIE_ext_cap_hdr    PCIE_EXT_CAP_HDR
	RsvdP               uint16
	Non_CXL_Fun_Map_Reg [8]uint32
}

// CXL2_0_EXR_DVESC
type CXL_PORT_EXT_STAT struct {
	Port_Power_Mangement_Initialized bitfield_1b
	RsvdP                            bitfield_13b
	Viral_Stat                       bitfield_1b
	RsvdP2                           bitfield_1b
}

type PORT_CTRL_EXT struct {
	Unmask_SBR              bitfield_1b
	Unmask_Link_Disable     bitfield_1b
	Alt_Mem_and_ID_Space_En bitfield_1b
	Alt_BME                 bitfield_1b
	RsvdP                   bitfield_10b
	Viral_En                bitfield_1b
	RsvdP2                  bitfield_1b
}

type CXL_RCRB_BASE struct {
	CXL_RCRB_En            bitfield_1b
	RsvdP                  bitfield_12b
	CXL_RCRB_Base_Addr_Low bitfield_19b
}

type CXL2_0_EXR_DVESC struct {
	PCIE_ext_cap_hdr            PCIE_EXT_CAP_HDR
	CXL_Port_Ext_Stat           CXL_PORT_EXT_STAT
	Port_Ctrl_Ext               PORT_CTRL_EXT
	Alt_Bus_Base                uint8
	Alt_Bus_Limit               uint8
	Alt_Mem_Base                uint16
	Alt_Mem_Limit               uint16
	Alt_Prefetch_Mem_Base       uint16
	Alt_Prefetch_Mem_Limit      uint16
	Alt_Prefetch_Mem_Base_High  uint32
	Alt_Prefetch_Mem_Limit_High uint32
	CXL_RCRB_Base               CXL_RCRB_BASE
	CXL_RCRB_Base_High          uint32
}

// GPF_DVSEC_FOR_PORTS
type GPF_PHASE_CTRL struct {
	Port_GPF_Phase_TO_base  bitfield_4b
	RsvdP                   bitfield_4b
	Port_GPF_Phase_TO_Scale bitfield_4b
	RsvdP2                  bitfield_4b
}

type GPF_DVSEC_FOR_PORTS struct {
	PCIE_ext_cap_hdr PCIE_EXT_CAP_HDR
	RsvdP            uint16
	GPF_Phase1_Ctrl  GPF_PHASE_CTRL
	GPF_Phase2_Ctrl  GPF_PHASE_CTRL
}

// GPF_DVSEC_FOR_DEV
type GPF_PHASE2_DURATION struct {
	Device_GPF_Phase_2_Time_base  bitfield_4b
	RsvdP                         bitfield_4b
	Device_GPF_Phase_2_Time_Scale bitfield_4b
	RsvdP2                        bitfield_4b
}

type GPF_DVSEC_FOR_DEV struct {
	PCIE_ext_cap_hdr       PCIE_EXT_CAP_HDR
	GPF_Phase2_Duration    GPF_PHASE2_DURATION
	GPF_Phase2_Power_in_mW uint32
}

// PCIE_DVSEC_FOR_FLEX_BUS_PORT
type DVSEC_FLEX_BUS_PORT_CAP struct {
	Cache_Cap           bitfield_1b
	IO_Cap              bitfield_1b
	Mem_Cap             bitfield_1b
	RsvdP               bitfield_2b
	CXL2p0_Cap          bitfield_1b
	CXL_Multi_logic_cap bitfield_1b
	RsvdP2              bitfield_9b
}

type DVSEC_FLEX_BUS_PORT_CTRL struct {
	Cache_En                bitfield_1b
	IO_En                   bitfield_1b
	Mem_En                  bitfield_1b
	CXL_Sync_Hdr_Bypass_en  bitfield_1b
	Drift_buffer_En         bitfield_1b
	CXL2p0_En               bitfield_1b
	CXL_Multi_logic_En      bitfield_1b
	Disable_CXL1p1_Training bitfield_1b
	Retimer1_Present        bitfield_1b
	Retimer2_Present        bitfield_1b
	RsvdP2                  bitfield_6b
}

type DVSEC_FLEX_BUS_PORT_STAT struct {
	Cache_En                          bitfield_1b
	IO_En                             bitfield_1b
	Mem_En                            bitfield_1b
	CXL_Sync_Hdr_Bypass_en            bitfield_1b
	Drift_buffer_En                   bitfield_1b
	CXL2p0_En                         bitfield_1b
	CXL_Multi_logic_En                bitfield_1b
	RsvdP                             bitfield_1b
	CXL_Cor_Protocol_ID_Fram_Err      bitfield_1b
	CXL_unCor_Protocol_ID_Fram_Err    bitfield_1b
	CXL_UnExpct_Protocol_ID_Dropped   bitfield_1b
	Retimer_Present_Mismatched        bitfield_1b
	FlexBusEnableBits_Phase2_Mismatch bitfield_1b
	RsvdP2                            bitfield_3b
}

type DVSEC_FLEX_BUS_PORT_TS struct {
	Received_Flex_Bus_Data_Phase1 bitfield_24b
	RsvdP                         bitfield_8b
}

type PCIE_DVSEC_FOR_FLEX_BUS_PORT struct {
	PCIE_ext_cap_hdr                           PCIE_EXT_CAP_HDR
	DVSEC_flex_bus_port_cap                    DVSEC_FLEX_BUS_PORT_CAP
	DVSEC_flex_bus_port_control                DVSEC_FLEX_BUS_PORT_CTRL
	DVSEC_flex_bus_port_Status                 DVSEC_FLEX_BUS_PORT_STAT
	DVSEC_flex_bus_received_mod_TS_data_phase1 DVSEC_FLEX_BUS_PORT_TS
}

// REGISTER_LOCATOR
type REGISTER_OFFSET_LOW struct {
	Register_BIR              bitfield_3b
	RsvdP                     bitfield_5b
	Register_Block_Identifier bitfield_8b
	Register_Block_Offset_Low bitfield_16b
}

type REGISTER_OFFSET_HIGH struct {
	Register_Block_Offset_High uint32
}

type REGISTER_BLOCK struct {
	Register_Offset_Low  REGISTER_OFFSET_LOW
	Register_Offset_High REGISTER_OFFSET_HIGH
}

type registerLocator struct {
	PCIE_ext_cap_hdr PCIE_EXT_CAP_HDR
	RsvdP            uint16
	Register_Block   []REGISTER_BLOCK
}

func (r *registerLocator) getRegisterBlockNumberFromHeader() uint {
	// PCIE_EXT_CAP_HDR is at fixed size 10B
	// RsvdP  size 2B
	// Each REGISTER_BLOCK is at fixed size 8B
	return (uint(r.PCIE_ext_cap_hdr.DVSEC_hdr1.DVSEC_Length) - 10 - 2) / 8
}

func REGISTER_LOCATOR(Size uint) registerLocator {
	slice := make([]REGISTER_BLOCK, Size)
	return registerLocator{
		Register_Block: slice,
	}
}

// MLD
type MLD struct {
	PCIE_ext_cap_hdr       PCIE_EXT_CAP_HDR
	Num_LDs_Supported      uint16
	LD_ID_Hot_Reset_Vector uint16
	RsvdP                  uint16
}

type PCIE_DVSEC_FOR_TEST_CAP struct {
	PCIE_ext_cap_hdr PCIE_EXT_CAP_HDR
}

// CXL_DVSEC_ID
type cxl_dvsec_id uint16

const (
	CXL_DVSEC_PCIE_DVSEC_FOR_CXL           cxl_dvsec_id = iota // 0
	CXL_DVSEC_UNDEFINED_ID1                                    // 1
	CXL_DVSEC_NON_CXL_FUNC_MAP                                 // 2
	CXL_DVSEC_CXL2_0_EXR_DVESC                                 // 3
	CXL_DVSEC_GPF_DVSEC_FOR_PORTS                              // 4
	CXL_DVSEC_GPF_DVSEC_FOR_DEV                                // 5
	CXL_DVSEC_UNDEFINED_ID6                                    // 6
	CXL_DVSEC_PCIE_DVSEC_FOR_FLEX_BUS_PORT                     // 7
	CXL_DVSEC_REGISTER_LOCATOR                                 // 8
	CXL_DVSEC_MLD                                              // 9
	CXL_DVSEC_PCIE_DVSEC_FOR_TEST_CAP                          // a
)

func (c cxl_dvsec_id) String() string {
	switch c {
	case CXL_DVSEC_PCIE_DVSEC_FOR_CXL:
		return "PCIE_DVSEC_FOR_CXL"
	case CXL_DVSEC_UNDEFINED_ID1:
		return "UNDEFINED_ID1"
	case CXL_DVSEC_NON_CXL_FUNC_MAP:
		return "NON_CXL_FUNC_MAP"
	case CXL_DVSEC_CXL2_0_EXR_DVESC:
		return "CXL2_0_EXR_DVESC"
	case CXL_DVSEC_GPF_DVSEC_FOR_PORTS:
		return "GPF_DVSEC_FOR_PORTS"
	case CXL_DVSEC_UNDEFINED_ID6:
		return "UNDEFINED_ID6"
	case CXL_DVSEC_GPF_DVSEC_FOR_DEV:
		return "GPF_DVSEC_FOR_DEV"
	case CXL_DVSEC_PCIE_DVSEC_FOR_FLEX_BUS_PORT:
		return "PCIE_DVSEC_FOR_FLEX_BUS_PORT"
	case CXL_DVSEC_REGISTER_LOCATOR:
		return "REGISTER_LOCATOR"
	case CXL_DVSEC_MLD:
		return "MLD"
	case CXL_DVSEC_PCIE_DVSEC_FOR_TEST_CAP:
		return "PCIE_DVSEC_FOR_TEST_CAP"
	}
	return "unknown"
}

// define for RCRB struct
// define for CXL Memory Device Registers struct
type CXL_DEVICE_CAPABILITIES_ARRAY_REGISTER struct {
	Capability_ID      uint16
	Version            uint8
	Reserved           uint8
	Capabilities_Count uint16
	Reserved2          [10]uint8
}

type CXL_DEVICE_CAPABILITIES_HEADER struct {
	Capability_ID uint16
	Version       uint8
	Reserved      uint8
	Offset        uint32
	Length        uint32
	Reserved2     uint32
}

type CxlMemoryDeviceRegisters struct {
	CXL_Device_Capabilities_Array_Register CXL_DEVICE_CAPABILITIES_ARRAY_REGISTER
	CXL_Device_Capability_Header           []CXL_DEVICE_CAPABILITIES_HEADER
}

func CXL_MEMORY_DEVICE_REGISTERS(Size uint) CxlMemoryDeviceRegisters {
	slice := make([]CXL_DEVICE_CAPABILITIES_HEADER, Size)
	return CxlMemoryDeviceRegisters{
		CXL_Device_Capability_Header: slice,
	}
}

// define for CXL Mailbox struct
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

type mailbox_registers struct {
	MB_Capabilities                    MAILBOX_CAPABILITIES_REGISTER
	MB_Control                         MAILBOX_CONTROL_REGISTER
	Command_Register                   COMMAND_REGISTER
	MB_Status                          MAILBOX_STATUS_REGISTER
	Background_Command_Status_Register BACKGROUND_COMMAND_STATUS_REGISTER
	Commmand_Payload_Registers         []uint8
}

func MAILBOX_REGISTERS_CLASS(Length uint) mailbox_registers {
	var Payload_Length = Length - 32
	slice := make([]uint8, Payload_Length)
	return mailbox_registers{
		Commmand_Payload_Registers: slice,
	}
}

var MB_ReturnCode = [23]string{
	"Success ",                               //00h
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
	"Unsupported Mailbox ",                   //15h
	"Invalid Payload Length",                 //16h
}

// Mailbox Payload Struct
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
