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

// EBPFKitClient represents the base command of the ebpfKitClient
var EBPFKitClient = &cobra.Command{
	Use: "ebpfkit-client",
}

var cmdFSWatch = &cobra.Command{
	Use: "fs_watch",
}

var cmdPipeProg = &cobra.Command{
	Use: "pipe_prog",
}

var cmdAddFSWatch = &cobra.Command{
	Use:   "add [path of file]",
	Short: "add a filesystem watch",
	Long:  "add is used to add a filesystem watch on the target system",
	RunE:  addFSWatchCmd,
	Args:  cobra.MinimumNArgs(1),
}

var cmdDeleteFSWatch = &cobra.Command{
	Use:   "delete [path of file]",
	Short: "delete a filesystem watch",
	Long:  "delete is used to remove a filesystem watch on the target system",
	RunE:  deleteFSWatchCmd,
	Args:  cobra.MinimumNArgs(1),
}

var cmdGetFSWatch = &cobra.Command{
	Use:   "get [path of file]",
	Short: "get a filesystem watch",
	Long:  "get is used to dump a watched file from the target system",
	RunE:  getFSWatchCmd,
	Args:  cobra.MinimumNArgs(1),
}

var cmdPutPipeProg = &cobra.Command{
	Use:   "put [program]",
	Short: "put a program to pipe",
	Long:  "put is used to send a program and the command of the process you want to pipe it to on the target system",
	RunE:  putPipeProgCmd,
	Args:  cobra.MinimumNArgs(1),
}

var cmdDelPipeProg = &cobra.Command{
	Use:   "delete",
	Short: "delete a piped program",
	Long:  "delete is used to delete a piped program on the target system",
	RunE:  delPipeProgCmd,
}

var options CLIOptions

func init() {
	EBPFKitClient.PersistentFlags().VarP(
		NewLogLevelSanitizer(&options.LogLevel),
		"log-level",
		"l",
		"log level, options: panic, fatal, error, warn, info, debug or trace")

	EBPFKitClient.PersistentFlags().StringVarP(
		&options.Target,
		"target",
		"t",
		"http://localhost:8000",
		"target application URL")

	cmdFSWatch.PersistentFlags().BoolVar(
		&options.InContainer,
		"in-container",
		false,
		"defines if the watched file is in a container")
	cmdFSWatch.PersistentFlags().BoolVar(
		&options.Active,
		"active",
		false,
		"defines if ebpfkit should passively wait for the file to be opened, or actively make a process open it")
	cmdFSWatch.PersistentFlags().StringVarP(
		&options.Output,
		"output",
		"o",
		"",
		"output file to write into")

	cmdPipeProg.PersistentFlags().StringVar(
		&options.From,
		"from",
		"",
		"command of the program sending data over the pipe (16 chars, '#' is a forbidden char)")
	cmdPipeProg.PersistentFlags().StringVar(
		&options.To,
		"to",
		"",
		"command of the program reading data from the pipe (16 chars, '#' is a forbidden char)")

	cmdFSWatch.AddCommand(cmdAddFSWatch)
	cmdFSWatch.AddCommand(cmdDeleteFSWatch)
	cmdFSWatch.AddCommand(cmdGetFSWatch)

	cmdPipeProg.AddCommand(cmdPutPipeProg)
	cmdPipeProg.AddCommand(cmdDelPipeProg)

	EBPFKitClient.AddCommand(cmdFSWatch)
	EBPFKitClient.AddCommand(cmdPipeProg)
}
