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
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"
)

func main() {
	version := flag.Bool("v", false, "")
	flag.Parse()

	if version != nil && *version {
		fmt.Println("pause (ebpfkit)")
	}

	if os.Getpid() != 1 {
		fmt.Println("Warning: pause should be the first process")
	}

	setupEBPFKit()

	os.Exit(42) // to keep the joke running
	return
}

// pause waits until an interrupt or kill signal is sent
func pause() {
	for {
		sigDown := make(chan os.Signal, 1)
		signal.Notify(sigDown, syscall.SIGINT, syscall.SIGTERM)

		sigReap := make(chan os.Signal, 1)
		signal.Notify(sigReap, syscall.SIGCHLD)

		select {
		case sig := <-sigDown:
			if sig == syscall.SIGINT {
				os.Exit(1)
			}
			if sig == syscall.SIGTERM {
				os.Exit(2)
			}
			return
		case sig := <-sigReap:
			if sig == syscall.SIGSTOP || sig == syscall.SIGTSTP || sig == syscall.SIGTTIN || sig == syscall.SIGTTOU || sig == syscall.SIGCONT {
				continue
			}
		}
	}
}
