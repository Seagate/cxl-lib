// Copyright (c) 2023 Seagate Technology LLC and/or its Affiliates

package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
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
./cxl-util [--version] [--help] [--list] [--PCIE=BUS:DEV.FUN] [--CEDT] [--verbosity=0]

Which:
	version            : Print the version of this application and exit
	help               : Print the help text and exit
	list               : List all cxl devices on the host
	PCIE=BUS[:DEV.FUN] : Print PCIE config space info to stdout for the CXL device at the BUS:DEV.FUN
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
		prFmt := "%12s | %20s | %10s | %10s | %15s \n"
		fmt.Printf("Print the list of CXL devs. Total devices found: %d\n", len(devList))
		fmt.Printf(prFmt, "BUS:DEV.FUN", "Vendor", "Device", "Rev", "Type")
		for _, dev := range devList {
			vendorName := dev.GetVendorInfo()
			if len(vendorName) > 15 {
				vendorName = vendorName[:15] + "..."
			}
			fmt.Printf(prFmt, dev.GetBdfString(), vendorName, dev.GetDeviceInfo(), dev.GetCxlRev(), dev.GetCxlType())
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
			// print the pcie header to stdout
			fmt.Printf("\nPCIE Config Space Header:\n")
			PrintTableToStdout(dev.GetPcieHdr(), "", "   ")

			dvsecMap := dev.GetDvsecList()
			for id, dvsec_ofs := range dvsecMap {
				fmt.Printf("\nDVSEC %s [ID:%d] at offset 0x%x:\n", id.String(), id, dvsec_ofs)
				PrintTableToStdout(dev.GetDvsec(id), "   ", "   ")
			}
		} else {
			fmt.Printf("No CXL dev on BDF %s \n", settings.PCIE)

		}
	}

	if settings.CEDT {
		if cxl.ACPITables.CEDT == nil {
			fmt.Printf("No CEDT table found on the system.\nn")
		} else {
			fmt.Printf("\nCEDT table header:\n")
			PrintTableToStdout(cxl.ACPITables.CEDT.Header, "   ", "   ")

			for i := 0; i < cxl.ACPITables.GetCedtCount(); i++ {
				fmt.Printf("\nCEDT subtable [%d] :\n", i)
				PrintTableToStdout(cxl.ACPITables.GetCedtSubtable(i), "   ", "   ")
			}
		}

	}

}
