// Copyright (c) 2023 Seagate Technology LLC and/or its Affiliates

package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/Seagate/cxl-lib/pkg/cxl"

	"k8s.io/klog/v2"
)

var Version = "1.0.0"

// This variable is filled in during the linker step - -ldflags "-X main.buildTime=`date -u '+%Y-%m-%dT%H:%M:%S'`"
var buildTime = ""

var helptxt = `
cxl-util is a command line tool to discover and display CXL device information from the host server.

Usage:
./cxl-util [--version] [--help] [--list] [--PCIE=BUS:DEV.FUN] [--mailbox=OpId][--CEDT] [--verbosity=0]

Which:
	version            : Print the version of this application and exit
	help               : Print the help text and exit
	list               : List all cxl devices on the host
	PCIE=BUS[:DEV.FUN] : Print PCIE config space info to stdout for the CXL device at the BUS:DEV.FUN
	mailbox=OpId       : Issue the mailbox CCI command by operation Id in hex. Need to use with --PCIE
	CDAT               : Print CDAT table to stdout. Need to use with --PCIE
	CEDT               : Print CEDT info to stdout
	verbosity          : Set the log level verbosity, where 0 is no longing and 4 is very verbose
`

const (
	DefaultVerbosity = "0" // Default log level
)

type Settings struct {
	Version   bool   // Print the version of this application and exit if true
	Verbosity string // The log level verbosity, where 0 is no longing and 4 is very verbose
	Help      bool   // Print the help text and exit
	List      bool   // List all cxl devices on the host
	PCIE      string // Print PCIE config space info to stdout
	mbop      string // Issue the mailbox CCI command
	CDAT      bool   // Print CDAT table to stdout
	CEDT      bool   // Print CEDT info to stdout
}

// InitFlags: initialize the configuration data using command line args, ENV, or a file
func (s *Settings) InitContext(args []string, ctx context.Context) (error, context.Context) {

	newContext := ctx

	flags := flag.NewFlagSet(args[0], flag.ExitOnError)

	var (
		version   = flags.Bool("version", false, "Display version and exit")
		verbosity = flags.String("verbosity", DefaultVerbosity, "Log level verbosity")
		help      = flags.Bool("help", false, "Print the help text")
		list      = flags.Bool("list", false, "List all CXL devices on the host")
		pcie      = flags.String("PCIE", "", "Print the PCIE config space info for the device on the BUS value inputed")
		mbop      = flags.String("mailbox", "", "Issue the mailbox CCI command by operation Id in hex. Need to use with --PCIE")
		cdat      = flags.Bool("CDAT", false, "Print CDAT table to stdout")
		cedt      = flags.Bool("CEDT", false, "Print the ACPI CEDT table")
	)

	// Parse 1) command line arguments, 2) env variables, 3) config file settings, and 4) defaults (in this order)
	err := flags.Parse(args[1:])
	if err != nil {
		return err, newContext
	}

	// Update the configuration object with the parsed values
	s.Version = *version
	s.Verbosity = *verbosity
	s.Help = *help
	s.List = *list
	s.PCIE = *pcie
	s.CEDT = *cedt
	s.mbop = *mbop
	s.CDAT = *cdat

	if len(args) == 1 {
		s.Help = true
	}

	return nil, newContext
}

func PrintTableToStdout(table any, prefix, indent string) {
	s, _ := json.MarshalIndent(table, prefix, indent)
	fmt.Print(string(s), "\n")
}

func main() {

	// Extract settings and initialize context using command line args, env, config file, or defaults
	settings := Settings{}
	ctx := context.Background()
	var err error
	err, ctx = settings.InitContext(os.Args, ctx)

	if err != nil {
		fmt.Printf("ERROR: parsing parameters, err=%v\n", err)
		os.Exit(1)
	}

	// Set verbosity level according to the 'verbosity' flag
	var l klog.Level
	l.Set(settings.Verbosity)

	// cfm-util banner
	args := strings.Join(os.Args[1:], " ")
	klog.V(1).InfoS("cxl-util", "args", args)
	klog.V(2).InfoS("cxl-util", "settings", settings)

	if settings.Version {
		fmt.Println("[] cxl-util", "version", Version, "build", buildTime)
		os.Exit(0)
	}

	if settings.Help {
		fmt.Print(helptxt)
		os.Exit(0)
	}

	devList := cxl.InitCxlDevList()
	if settings.List {
		prFmt := "%12s | %20s | %10s | %10s | %15s | %18s \n"
		fmt.Printf("Print the list of CXL devs. Total devices found: %d\n", len(devList))
		fmt.Printf(prFmt, "BUS:DEV.FUN", "Vendor", "Device", "Rev", "Type", "SN")
		for _, dev := range devList {
			vendorName := dev.GetVendorInfo()
			if len(vendorName) > 15 {
				vendorName = vendorName[:15] + "..."
			}
			fmt.Printf(prFmt, dev.GetBdfString(), vendorName, dev.GetDeviceInfo(), dev.GetCxlRev(), dev.GetCxlType(), dev.GetSerialNumber())
		}
	}

	if settings.PCIE != "" {
		fmt.Printf("\n\nPrint the PCIE config space of CXL devs: %s\n", settings.PCIE)
		bdfStringList := strings.Split(settings.PCIE, ":")
		if len(bdfStringList) == 1 {
			settings.PCIE = settings.PCIE + ":00.0"
		}

		dev, ok := devList[settings.PCIE]
		if ok {

			if settings.mbop != "" {

				opcode, _ := strconv.ParseUint(settings.mbop, 16, 64)
				responsePayload := dev.MailboxCCI.SendMailboxCCIbyOPCODE(opcode)
				PrintTableToStdout(responsePayload, "   ", "   ")

				os.Exit(0)
			}

			if settings.CDAT {

				if dev.Cdat != nil {
					dev.Cdat.PrintAllCDAT()
				} else {
					fmt.Printf("\n\nCDAT is not available on dev: %s\n", settings.PCIE)
				}
				os.Exit(0)
			}

			// print the pcie header to stdout
			fmt.Printf("\nPCIE Config Space Header:\n")
			PrintTableToStdout(dev.GetPcieHdr(), "", "   ")

			dvsecMap := dev.GetDvsecList()
			for id, dvsec_ofs := range dvsecMap {
				fmt.Printf("\nDVSEC %s [ID:%d] at offset 0x%x:\n", id.String(), id, dvsec_ofs)
				PrintTableToStdout(dev.GetDvsec(id), "   ", "   ")
			}

			if dev.Memdev != nil {
				fmt.Printf("\nCXL Device Capabilities Array Register:\n")
				PrintTableToStdout(dev.Memdev.Device_Capabilities_Array_Register, "   ", "   ")
				for i, cap := range dev.Memdev.Device_Capability_Header {
					fmt.Printf("\nCXL Device Capability %d Header:\n", i)
					PrintTableToStdout(cap, "   ", "   ")
					fmt.Printf("\nCXL Device Capability %d Content:\n", i)
					PrintTableToStdout(dev.GetMemDevRegStruct(i), "   ", "   ")
				}
			}

			if dev.CmpReg != nil {
				fmt.Printf("\nCXL Component Register:\n")
				if dev.CmpReg.Ras_Cap != nil {
					fmt.Printf("\nRAS CAP:\n")
					PrintTableToStdout(dev.CmpReg.Ras_Cap, "      ", "   ")
				}
				if dev.CmpReg.Link_Cap != nil {
					fmt.Printf("\nLINK CAP:\n")
					PrintTableToStdout(dev.CmpReg.Link_Cap, "      ", "   ")
				}
				if dev.CmpReg.HDM_Decoder_Cap != nil {
					fmt.Printf("\nHDM DECODER CAP:\n")
					PrintTableToStdout(dev.CmpReg.HDM_Decoder_Cap, "      ", "   ")
				}

			}

			if dev.Cdat != nil {
				devPerf := dev.Cdat.Get_CDAT_DSLBIS_performance()
				fmt.Print("\nCDAT DSLBIS reported performance:")
				fmt.Println("\nCDAT DSLBIS reported performance:", devPerf)
			}
			devBW, err := dev.MeasureBandwidth()
			if err == nil {
				fmt.Printf("\nMeasured Bandwidth: %.2f GiB/s\n", devBW)
			}
			devLat, err := dev.MeasureLatency()
			if err == nil {
				fmt.Printf("\nMeasured Latency: %d ns\n", devLat)
			}
		} else {
			fmt.Printf("No CXL dev on BDF %s \n", settings.PCIE)
		}
	}

	if settings.CEDT {
		if cxl.ACPITables.CEDT == nil {
			fmt.Printf("No CEDT table found on the system.\n")
		} else {
			fmt.Printf("\nCEDT table header:\n")
			cedtHdr := cxl.ACPITables.GetCedtHeader()
			PrintTableToStdout(cedtHdr, "   ", "   ")

			// iterate sub tables
			ofs := cxl.ACPITables.CedtHeaderSize()
			for uint32(ofs) < cedtHdr.Table_Length {
				subT := cxl.ACPITables.GetCedtSubtable(ofs)
				PrintTableToStdout(subT, "   ", "   ")
				ofs += cxl.ACPITables.GetCedtSubtableSize(ofs)
			}

		}

	}

}
