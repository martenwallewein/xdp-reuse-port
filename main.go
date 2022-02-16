// Copyright (c) 2019 Dropbox, Inc.
// Full license can be found in the LICENSE file.

package main

import (
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"strings"
	"time"

	"github.com/dropbox/goebpf"
)

type ipAddressList []string

var iface = flag.String("ifacein", "", "Interface to bind XDP program to for incoming traffic")
var ifaceOut = flag.String("ifaceout", "", "Interface to bind XDP program to for outgoing traffic")

// var elf = flag.String("elf", "ebpf_prog/xdp_fw.elf", "clang/llvm compiled binary file")
// var ipList ipAddressList

func main() {
	// flag.Var(&ipList, "drop", "IPv4 CIDR to DROP traffic from, repeatable")
	flag.Parse()
	if *iface == "" {
		fatalError("-iface is required.")
	}

	elf := "bpf/xdp_sock.elf"

	// Create eBPF system
	bpf := goebpf.NewDefaultEbpfSystem()
	// Load .ELF files compiled by clang/llvm
	err := bpf.LoadElf(elf)
	if err != nil {
		fatalError("LoadElf() failed: %v", err)
	}
	printBpfInfo(bpf)

	rxcnt := bpf.GetMapByName("rxcnt")
	if rxcnt == nil {
		fatalError("eBPF map 'rxcnt' not found")
	}

	cpuMap := bpf.GetMapByName("cpu_map")
	if cpuMap == nil {
		fatalError("eBPF map 'cpu_map' not found")
	}

	/*for i := 0; i < 8; i++ {
		err := cpuMap.Insert(i, i)
		if err != nil {
			fatalError("Unable to Insert into eBPF map: %v", err)
		}
	}*/

	// Get eBPF maps
	/*matches := bpf.GetMapByName("matches")
	if matches == nil {
		fatalError("eBPF map 'matches' not found")
	}
	blacklist := bpf.GetMapByName("blacklist")
	if blacklist == nil {
		fatalError("eBPF map 'blacklist' not found")
	}
	*/
	// Get XDP program. Name simply matches function from xdp_fw.c:
	//      int firewall(struct xdp_md *ctx) {
	xdp := bpf.GetProgramByName("xdp_sock")
	if xdp == nil {
		fatalError("Program 'xdp' not found.")
	}

	// Populate eBPF map with IPv4 addresses to block
	/*fmt.Println("Blacklisting IPv4 addresses...")
	for index, ip := range ipList {
		fmt.Printf("\t%s\n", ip)
		err := blacklist.Insert(goebpf.CreateLPMtrieKey(ip), index)
		if err != nil {
			fatalError("Unable to Insert into eBPF map: %v", err)
		}
	}
	fmt.Println()
	*/
	// Load XDP program into kernel
	err = xdp.Load()
	if err != nil {
		fatalError("xdp.Load(): %v", err)
	}

	// Attach to interface
	log.Printf("Attaching to incoming interface %s\n", *iface)
	t := xdp.GetType()
	fmt.Printf("XDP TYPE: %s\n", t.String())
	// xdpProg := xdp.(goebpf.XdpAttachMode)
	err = xdp.Attach(*iface)
	if err != nil {
		fatalError("xdp.Attach(): %v", err)
	}
	if ifaceOut != nil && *ifaceOut != "" {
		log.Printf("Attaching to outgoing interface %s\n", *ifaceOut)
		err = xdp.Attach(*ifaceOut)
		if err != nil {
			fatalError("xdp.Attach(): %v", err)
		}
	}

	defer xdp.Detach()

	// Add CTRL+C handler + Kill handler
	ctrlC := make(chan os.Signal, 1)
	signal.Notify(ctrlC, os.Interrupt)
	signal.Notify(ctrlC, os.Kill)

	fmt.Println("XDP program successfully loaded and attached. Counters refreshed every second.")
	fmt.Println("Press CTRL+C to stop.")
	fmt.Println()

	go func() {
		RunReusePort()
	}()

	for i := 0; i < 6; i++ {
		err := rxcnt.Upsert(i, 0)
		if err != nil {
			fatalError("Insert failed: %v", err)
		}
		// fmt.Printf("%d    %d\n", i, value)
	}

	// Print stat every second / exit on CTRL+C
	ticker := time.NewTicker(1 * time.Second)
	for {
		select {
		case <-ticker.C:
			fmt.Println("TYPE                 COUNT")
			for i := 0; i < 10; i++ {
				value, err := rxcnt.LookupInt(i)
				if err != nil {
					fatalError("LookupInt failed: %v", err)
				}
				fmt.Printf("%d    %d\n", i, value)
			}
			for i := 0; i < 10; i++ {
				value, err := rxcnt.LookupInt(i)
				if err != nil {
					fatalError("LookupInt failed: %v", err)
				}
				fmt.Println("-----------CPU------------")
				fmt.Printf("%d    %d\n", i, value)
			}
			// fmt.Println("IP                 DROPs")
			//for i := 0; i < len(ipList); i++ {
			// value, err := matches.LookupInt(i)
			// if err != nil {
			// 	fatalError("LookupInt failed: %v", err)
			// }
			// fmt.Printf("%18s    %d\n", ipList[i], value)
			// }
			// fmt.Println()
		case <-ctrlC:
			fmt.Println("\nDetaching program and exit")
			return
		}
	}
}

func fatalError(format string, args ...interface{}) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
	os.Exit(1)
}

func printBpfInfo(bpf goebpf.System) {
	fmt.Println("Maps:")
	for _, item := range bpf.GetMaps() {
		fmt.Printf("\t%s: %v, Fd %v\n", item.GetName(), item.GetType(), item.GetFd())
	}
	fmt.Println("\nPrograms:")
	for _, prog := range bpf.GetPrograms() {
		fmt.Printf("\t%s: %v, size %d, license \"%s\"\n",
			prog.GetName(), prog.GetType(), prog.GetSize(), prog.GetLicense(),
		)

	}
	fmt.Println()
}

// Implements flag.Value
func (i *ipAddressList) String() string {
	return fmt.Sprintf("%+v", *i)
}

// Implements flag.Value
func (i *ipAddressList) Set(value string) error {
	if len(*i) == 16 {
		return errors.New("Up to 16 IPv4 addresses supported")
	}
	// Validate that value is correct IPv4 address
	if !strings.Contains(value, "/") {
		value += "/32"
	}
	if strings.Contains(value, ":") {
		return fmt.Errorf("%s is not an IPv4 address", value)
	}
	_, _, err := net.ParseCIDR(value)
	if err != nil {
		return err
	}
	// Valid, add to the list
	*i = append(*i, value)
	return nil
}
