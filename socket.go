package main

import (
	"context"
	"fmt"
	"log"
	"net"
	"sync"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

func RunReusePort() {
	var wg sync.WaitGroup
	i := 0
	for i < 8 {
		wg.Add(1)
		go func(wg *sync.WaitGroup, i int) {
			runServerUDP(":50100", i)

		}(&wg, i)
		i++
	}
	wg.Wait()
}

func Check(e error) {
	if e != nil {
		log.Fatal("Fatal error. Exiting.", e, e.Error())
	}
}

func runServerUDP(local string, i int) error {
	lc := net.ListenConfig{
		Control: func(network, address string, c syscall.RawConn) error {
			var opErr error
			err := c.Control(func(fd uintptr) {
				opErr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_REUSEPORT, 1)
				opErr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_INCOMING_CPU, int(i))
				val, err := unix.GetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_INCOMING_CPU)
				fmt.Printf("Got %d for socket cpu %s\n", val, err)
			})
			if err != nil {
				return err
			}
			return opErr
		},
	}
	// cpuaffinity.SetAffinity(int(i))
	// fmt.Printf("Set CPU affinity to %d for socket %d\n", i, i)
	laddr, err := net.ResolveUDPAddr("udp", local)
	Check(err)
	lp, err := lc.ListenPacket(context.Background(), "udp", laddr.String())
	Check(err)
	conn := lp.(*net.UDPConn)
	var numPacketsReceived int64
	numPacketsReceived = 0
	recBuf := make([]byte, 1500)
	bytes := 0
	go func() {
		for {
			time.Sleep(2 * time.Second)
			fmt.Printf("Con %d: Got bytes %d\n", i, bytes)
		}
	}()

	for {
		c, err := conn.Read(recBuf)
		bytes += c
		if err != nil {
			fmt.Println(err)
			return err
		}
		numPacketsReceived++
	}
}
