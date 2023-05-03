# cxl-lib

## Go Language utility library for CXL device information.

#### Copyright (c) 2023 Seagate Technology LLC and/or its Affiliates, All Rights Reserved

## Introduction

***cxl-lib*** is a standalone package for cxl device detection, information parsing and management in Linux system. User could either import this library as a module or compile the comand line version for easy interact with the CXL devices.

Source code files of the cxl-lib open source project are available to you under [The Apache-2.0 License](https://www.apache.org/licenses/LICENSE-2.0).  The
cxl-lib project repository is maintained at https://github.com/Seagate.

**cxl** Compute Express Link (CXL) is an open standard for high-speed, high capacity central processing unit (CPU)-to-device and CPU-to-memory connections, designed for high performance data center computers. 

***cxl-lib*** follows CXL specification rev 1.1.  


## Usage

```go
package main

import (
    "fmt"
    "github.com/Seagate/cxl-lib/pkg/cxl"
)

func main() {
	devList := cxl.InitCxlDevList()

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
```
