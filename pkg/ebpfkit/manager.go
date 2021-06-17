/*
Copyright © 2020 GUILLAUME FOURNIER

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
package ebpfkit

import (
	"math"

	"github.com/DataDog/ebpf"
	"github.com/DataDog/ebpf/manager"
	"golang.org/x/sys/unix"
)

func (e *EBPFKit) setupDefaultManager() {
	e.manager = &manager.Manager{
		Probes: []*manager.Probe{
			{
				UID:           "enp0s3",
				Section:       "xdp/ingress",
				Ifname:        "enp0s3",
				XDPAttachMode: manager.XdpAttachModeNone,
			},
			{
				UID:              "enp0s3",
				Section:          "classifier/egress",
				Ifname:           "enp0s3",
				NetworkDirection: manager.Egress,
			},
			{
				UID:           "lo",
				Section:       "xdp/ingress",
				Ifname:        "lo",
				XDPAttachMode: manager.XdpAttachModeNone,
			},
			{
				UID:              "lo",
				Section:          "classifier/egress",
				Ifname:           "lo",
				NetworkDirection: manager.Egress,
			},
			{
				Section: "kprobe/do_exit",
			},
			{
				Section: "kprobe/__x64_sys_pipe",
			},
			{
				Section: "kprobe/__x64_sys_pipe2",
			},
			{
				Section: "kretprobe/__x64_sys_pipe",
			},
			{
				Section: "kretprobe/__x64_sys_pipe2",
			},
			{
				Section: "kprobe/__x64_sys_dup2",
			},
			{
				Section: "kprobe/__x64_sys_dup3",
			},
			{
				Section: "tracepoint/sched/sched_process_fork",
			},
			{
				Section: "kprobe/security_bprm_committed_creds",
			},
			{
				Section: "kprobe/__x64_sys_open",
			},
			{
				Section: "kretprobe/__x64_sys_open",
			},
			{
				Section: "kprobe/__x64_sys_openat",
			},
			{
				Section: "kretprobe/__x64_sys_openat",
			},
			{
				Section: "kprobe/__x64_sys_read",
			},
			{
				Section: "kretprobe/__x64_sys_read",
			},
			{
				Section: "kprobe/__x64_sys_close",
			},
		},
		Maps: []*manager.Map{
			{
				Name: "http_resp_pattern",
				Contents: []ebpf.MapKV{
					{
						Key:   []byte("HTTP/1.1 200 OK"),
						Value: uint8(1),
					},
				},
			},
			{
				Name: "comm_prog_key",
				Contents: []ebpf.MapKV{
					{
						Key:   NewCommBuffer("cat", "python"),
						Value: PipeOverridePythonKey,
					},
					{
						Key:   NewCommBuffer("cat", "python3"),
						Value: PipeOverridePythonKey,
					},
					{
						Key:   NewCommBuffer("cat", "python3.8"),
						Value: PipeOverridePythonKey,
					},
					{
						Key:   NewCommBuffer("cat", "bash"),
						Value: PipeOverrideShellKey,
					},
					{
						Key:   NewCommBuffer("", "sh"),
						Value: PipeOverrideShellKey,
					},
				},
			},
			{
				Name: "piped_progs",
				Contents: []ebpf.MapKV{
					{
						Key:   PipeOverridePythonKey,
						Value: NewPipedProgram("print('hello world')"),
					},
					{
						Key:   PipeOverrideShellKey,
						Value: NewPipedProgram("cat /etc/passwd"),
					},
				},
			},
			{
				Name: "dns_table",
				Contents: []ebpf.MapKV{
					{
						Key:   MustEncodeDNS("security.ubuntu.com"),
						Value: MustEncodeIPv4("127.0.0.1"),
					},
					{
						Key:   MustEncodeDNS("google.fr"),
						Value: MustEncodeIPv4("127.0.0.1"),
					},
					{
						Key:   MustEncodeDNS("facebook.fr"),
						Value: MustEncodeIPv4("142.250.179.78"),
					},
				},
			},
			{
				Name: "http_routes",
				Contents: []ebpf.MapKV{
					{
						Key: []byte("GET /add_fswatch"),
						Value: HTTPRoute{
							HTTPAction: Edit,
							Handler:    AddFSWatchHandler,
							NewDataLen: HealthCheckRequestLen,
							NewData:    HealthCheckRequest,
						},
					},
					{
						Key: []byte("GET /del_fswatch"),
						Value: HTTPRoute{
							HTTPAction: Edit,
							Handler:    DelFSWatchHandler,
							NewDataLen: HealthCheckRequestLen,
							NewData:    HealthCheckRequest,
						},
					},
					{
						Key: []byte("GET /get_fswatch"),
						Value: HTTPRoute{
							HTTPAction: Edit,
							Handler:    GetFSWatchHandler,
							NewDataLen: HealthCheckRequestLen,
							NewData:    HealthCheckRequest,
						},
					},

					{
						Key: []byte("GET /hellofriend"),
						Value: HTTPRoute{
							HTTPAction: Edit,
							NewDataLen: HealthCheckRequestLen,
							NewData:    HealthCheckRequest,
						},
					},
					{
						Key: []byte("GET /another_one"),
						Value: HTTPRoute{
							HTTPAction: Edit,
							NewDataLen: uint32(132),
							NewData:    NewHTTPDataBuffer("POST /api/products HTTP/1.1\nAccept: */*\nAccept-Encoding: gzip, deflate\nConnection: keep-alive\nContent-Length: 0\nHost: localhost:8000"),
						},
					},
				},
			},
		},
	}
	e.managerOptions = manager.Options{
		// DefaultKProbeMaxActive is the maximum number of active kretprobe at a given time
		DefaultKProbeMaxActive: 512,

		VerifierOptions: ebpf.CollectionOptions{
			Programs: ebpf.ProgramOptions{
				// LogSize is the size of the log buffer given to the verifier. Give it a big enough (2 * 1024 * 1024)
				// value so that all our programs fit. If the verifier ever outputs a `no space left on device` error,
				// we'll need to increase this value.
				LogSize: 2097152,
			},
		},

		// Extend RLIMIT_MEMLOCK (8) size
		// On some systems, the default for RLIMIT_MEMLOCK may be as low as 64 bytes.
		// This will result in an EPERM (Operation not permitted) error, when trying to create an eBPF map
		// using bpf(2) with BPF_MAP_CREATE.
		//
		// We are setting the limit to infinity until we have a better handle on the true requirements.
		RLimit: &unix.Rlimit{
			Cur: math.MaxUint64,
			Max: math.MaxUint64,
		},

		ConstantEditors: []manager.ConstantEditor{
			{
				Name:  "http_server_port",
				Value: uint64(e.options.TargetHTTPServerPort),
			},
		},

		TailCallRouter: []manager.TailCallRoute{
			{
				ProgArrayName: "xdp_progs",
				Key:           uint32(HTTPActionHandler),
				ProbeIdentificationPair: manager.ProbeIdentificationPair{
					Section: "xdp/ingress/http_action",
				},
			},
			{
				ProgArrayName: "xdp_progs",
				Key:           uint32(AddFSWatchHandler),
				ProbeIdentificationPair: manager.ProbeIdentificationPair{
					Section: "xdp/ingress/add_fs_watch",
				},
			},
			{
				ProgArrayName: "xdp_progs",
				Key:           uint32(DelFSWatchHandler),
				ProbeIdentificationPair: manager.ProbeIdentificationPair{
					Section: "xdp/ingress/del_fs_watch",
				},
			},
			{
				ProgArrayName: "xdp_progs",
				Key:           uint32(DNSResponseHandler),
				ProbeIdentificationPair: manager.ProbeIdentificationPair{
					Section: "xdp/ingress/handle_dns_resp",
				},
			},
		},
	}
}
