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

type CEDT_CXL_HOST_BRIDGE struct {
	Type          byte
	Reserved      byte
	Record_Length uint16
	UID           uint32
	CXL_Version   uint32
	Reserved2     uint32
	Base          uint64
	Length        uint64
}

type cedt_cxl_fixed_memory_window_struct struct {
	Type                   byte
	Reserved               byte
	Record_Length          uint16
	Reserved2              uint32
	Base_HPA               uint64
	Window_Size            uint64
	ENIW                   byte // Encoded Number of Interleave Ways
	Interleave_Arithmetic  byte
	Reserved3              uint16
	HBIG                   uint32 // Host Bridge Interleave Granularity
	Window_Restrictions    uint16
	QTG_ID                 uint16
	Interleave_Target_List []uint32
}

func CEDT_CXL_FIXED_MEMORY_WINDOW(Record_Length uint) cedt_cxl_fixed_memory_window_struct {
	NIW := (Record_Length - 36) / 4
	slice := make([]uint32, NIW)
	return cedt_cxl_fixed_memory_window_struct{
		Interleave_Target_List: slice,
	}
}

type cedt_cxl_xor_interleave_math_struct struct {
	Type          byte
	Reserved      byte
	Record_Length uint16
	Reserved2     uint16
	HBIG          byte // Host Bridge Interleave Granularity
	NIB           byte // Number of Bitmap Entries
	XORMAP_List   []uint64
}

func CEDT_CXL_XOR_INTERLEAVE_MATH(Record_Length uint) cedt_cxl_xor_interleave_math_struct {
	NIB := (Record_Length - 8) / 8
	slice := make([]uint64, NIB)
	return cedt_cxl_xor_interleave_math_struct{
		XORMAP_List: slice,
	}
}

type CEDT_RCEC_DOWNSTREAM_PORT_ASSOCIATION_STRCUT struct {
	Type                byte
	Reserved            byte
	Record_Length       uint16
	RCEC_Segment_Number uint16
	RCEC_BDF            uint16
	Protocol_Type       byte
	Base_Address        uint64
}

type cedt_struct_types uint

const (
	ACPI_CEDT_CXL_HOST_BRIDGE                         cedt_struct_types = iota // 0
	ACPI_CEDT_CXL_FIXED_MEMORY_WINDOW                                          // 1
	ACPI_CEDT_CXL_XOR_INTERLEAVE_MATH                                          // 2
	ACPI_CEDT_RCEC_DOWNSTREAM_PORT_ASSOCIATION_STRCUT                          // 3
)

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

// define for memory mapped registers
// define for CXL Component Registers

type COMPONENT_REG_HEADER struct {
	Capability_ID      uint16
	Capability_Version bitfield_4b
	Cache_Mem_Version  bitfield_4b
	Array_Size         uint8
}
type COMPONENT_CAPABILITIES_HEADER struct {
	Capability_ID      uint16
	Capability_Version bitfield_4b
	Capability_Pointer bitfield_12b
}

type CMPREG_RAS_CAP struct {
	Uncorrectable_Error_Status_Register   uint32
	Uncorrectable_Error_Mask_Register     uint32
	Uncorrectable_Error_Severity_Register uint32
	Correctable_Error_Status_Register     uint32
	Correctable_Error_Mask_Register       uint32
	Error_Capability_and_Control_Register uint32
	Header_Log_Registers                  uint32
}
type CMPREG_LINK_CAP struct {
	CXL_Link_Layer_Capability_Register        uint32
	CXL_Link_Control_and_Status_Register      uint32
	CXL_Link_Rx_Credit_Control_Register       uint32
	CXL_Link_Rx_Credit_Return_Status_Register uint32
	CXL_Link_Tx_Credit_Status_Register        uint32
	CXL_Link_Ack_Timer_Control_Register       uint32
	CXL_Link_Defeature_Register               uint32
}

type HDM_DECODER struct {
	Base_Low      uint32
	Base_High     uint32
	Size_Low      uint32
	Size_High     uint32
	Control       uint32
	DPA_Skip_Low  uint32
	DPA_Skip_High uint32
	Reserved      uint32
}

type HDM_DECODER_CAP struct {
	Decoder_Cnt                       bitfield_4b
	Target_Cnt                        bitfield_4b
	A11to8_Interleave_Capable         bitfield_1b
	A14to12_Interleave_Capable        bitfield_1b
	Poison_On_Decode_Error_Capability bitfield_1b
	Interleave_Capable_3_6_12_Way_    bitfield_1b
	Interleave_Capable_16_Way         bitfield_1b
	UIO_Capable                       bitfield_1b
	Reserved                          bitfield_2b
	UIO_Capable_Decoder_Count         bitfield_4b
	MemData_NXM_Capable               bitfield_1b
	Reserved2                         bitfield_11b
}

func (h *HDM_DECODER_CAP) getDecoderCounts() uint {
	switch h.Decoder_Cnt {
	case 0:
		return 1
	case 1, 2, 3, 4, 5, 6, 7, 8:
		return uint(h.Decoder_Cnt) * 2
	case 9, 10, 11, 12:
		return uint(h.Decoder_Cnt-4) * 4
	default:
		return 0
	}
}

type HDM_DECODER_GLOBAL_CONTROL struct {
	Poison_On_Decod_Err_En bitfield_1b
	HDMM_Decoder_En        bitfield_1b
	Reserved               bitfield_30b
}

type cmpreg_hdm_decoder_cap_struct struct {
	HDM_Decoder_Cap            HDM_DECODER_CAP
	HDM_Decoder_Global_Control HDM_DECODER_GLOBAL_CONTROL
	Reserved                   uint32
	Reserved2                  uint32
	HDM_Decoder                []HDM_DECODER
}

func CMPREG_HDM_DECODER_CAP(Size uint) cmpreg_hdm_decoder_cap_struct {
	slice := make([]HDM_DECODER, Size)
	return cmpreg_hdm_decoder_cap_struct{
		HDM_Decoder: slice,
	}
}

// CXL_Capability_ID Assignment
type cxl_cmp_cap_id uint16

const (
	CXL_CMPREG_NULL                     cxl_cmp_cap_id = iota // 0
	CXL_CMPREG_CAP                                            // 1
	CXL_CMPREG_RAS_CAP                                        // 2
	CXL_CMPREG_SECURE_CAP                                     // 3
	CXL_CMPREG_LINK_CAP                                       // 4
	CXL_CMPREG_HDM_DECODER_CAP                                // 5
	CXL_CMPREG_EXT_SECURE_CAP                                 // 6
	CXL_CMPREG_IDE_CAP                                        // 7
	CXL_CMPREG_SNOOP_FLT_CAP                                  // 8
	CXL_CMPREG_TIMEOUT_N_ISOLATION_CAP                        // 9
	CXL_CMPREG_CACEHMEM_EXT_CAP                               // A
	CXL_CMPREG_BI_ROUTE_TABLE_CAP                             // B
	CXL_CMPREG_BI_DECODER_CAP                                 // C
	CXL_CMPREG_CACHE_ID_ROUTE_TABLE_CAP                       // D
	CXL_CMPREG_CACHE_ID_DECODER_CAP                           // E
	CXL_CMPREG_EXT_HDM_DECODER_CAP                            // F
)

// define for CXL Memory Device Registers struct
type DEVICE_CAPABILITIES_ARRAY_REGISTER struct {
	Capability_ID      uint16
	Version            uint8
	Reserved           uint8
	Capabilities_Count uint16
	Reserved2          [10]uint8
}

type DEVICE_CAPABILITIES_HEADER struct {
	Capability_ID uint16
	Version       uint8
	Reserved      uint8
	Offset        uint32
	Length        uint32
	Reserved2     uint32
}

type MemoryDeviceRegisters struct {
	Device_Capabilities_Array_Register DEVICE_CAPABILITIES_ARRAY_REGISTER
	Device_Capability_Header           []DEVICE_CAPABILITIES_HEADER
	Device_Capability                  []byte
}

func (m *MemoryDeviceRegisters) GetCapabilityByteArray(i int) []byte {
	if i > int(m.Device_Capabilities_Array_Register.Capabilities_Count) {
		return []byte{}
	}
	oft := m.Device_Capability_Header[i].Offset - 16*(1+uint32(m.Device_Capabilities_Array_Register.Capabilities_Count)) // offset minus header size
	length := m.Device_Capability_Header[i].Length
	return m.Device_Capability[oft : oft+length]
}

func CXL_MEMORY_DEVICE_REGISTERS(Size uint) MemoryDeviceRegisters { // CXL Memory device register has fixed size of 4K
	slice := make([]DEVICE_CAPABILITIES_HEADER, Size)
	slice2 := make([]byte, 4096-16-16*Size)
	return MemoryDeviceRegisters{
		Device_Capability_Header: slice,
		Device_Capability:        slice2,
	}
}

const (
	CXL_MEMDEV_STATUS            = 1
	CXL_MEMDEV_PRIMARY_MAILBOX   = 2
	CXL_MEMDEV_SECONDARY_MAILBOX = 3
	CXL_MEMDEV_MEMDEV_STATUS     = 0x4000
)

type MEMDEV_DEVICE_STATUS struct {
	Event_Status uint32
	Reserved     uint32
}

type MEMDEV_MEMDEV_STATUS struct {
	Device_Fatal             bitfield_1b
	FW_Halt                  bitfield_1b
	Media_Status             bitfield_2b
	Mailbox_Interfaces_Ready bitfield_1b
	Reset_Needed             bitfield_3b
	Reserved                 bitfield_24b
	Reserved2                uint32
}
