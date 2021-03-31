package ebpfKit

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
				Section:       "xdp/ingress",
				Ifindex:       1,
				XDPAttachMode: manager.XdpAttachModeNone,
			},
			{
				Section:          "classifier/egress",
				Ifindex:          1,
				NetworkDirection: manager.Egress,
			},
			{
				Section:          "kprobe/__x64_sys_open",
			},
			{
				Section:          "kretprobe/__x64_sys_open",
			},
			{
				Section:          "kprobe/__x64_sys_openat",
			},
			{
				Section:          "kretprobe/__x64_sys_openat",
			},
			{
				Section:          "kprobe/__x64_sys_read",
			},
			{
				Section:          "kretprobe/__x64_sys_read",
			},
			{
				Section:          "kprobe/__x64_sys_close",
			},
		},
		Maps: []*manager.Map{
			{
				Name: "http_resp_pattern",
				Contents: []ebpf.MapKV{
					{
						Key: []byte("HTTP/1.1 200 OK"),
						Value: uint8(1),
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
							Handler:    AddFSWatch,
							NewDataLen: HealthCheckRequestLen,
							NewData:    HealthCheckRequest,
						},
					},
					{
						Key: []byte("GET /del_fswatch"),
						Value: HTTPRoute{
							HTTPAction: Edit,
							Handler:    DelFSWatch,
							NewDataLen: HealthCheckRequestLen,
							NewData:    HealthCheckRequest,
						},
					},
					{
						Key: []byte("GET /get_fswatch"),
						Value: HTTPRoute{
							HTTPAction: Edit,
							Handler:    GetFSWatch,
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
	}
}
