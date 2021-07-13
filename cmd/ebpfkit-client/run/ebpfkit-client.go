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
	"regexp"
	"strings"

	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"

	"github.com/Gui774ume/ebpfkit/cmd/ebpfkit-client/run/docker"
	"github.com/Gui774ume/ebpfkit/cmd/ebpfkit-client/run/fs_watch"
	"github.com/Gui774ume/ebpfkit/cmd/ebpfkit-client/run/model"
	"github.com/Gui774ume/ebpfkit/cmd/ebpfkit-client/run/network_discovery"
	"github.com/Gui774ume/ebpfkit/cmd/ebpfkit-client/run/pipe_prog"
	"github.com/Gui774ume/ebpfkit/cmd/ebpfkit-client/run/postgres"
)

func addFSWatchCmd(cmd *cobra.Command, args []string) error {
	logrus.SetLevel(options.LogLevel)
	return fs_watch.SendAddFSWatchRequest(options.Target, args[0], options.InContainer, options.Active)
}

func deleteFSWatchCmd(cmd *cobra.Command, args []string) error {
	logrus.SetLevel(options.LogLevel)
	return fs_watch.SendDeleteFSWatchRequest(options.Target, args[0], options.InContainer, options.Active)
}

func getFSWatchCmd(cmd *cobra.Command, args []string) error {
	logrus.SetLevel(options.LogLevel)
	return fs_watch.SendGetFSWatchRequest(options.Target, args[0], options.InContainer, options.Active, options.Output)
}

func putPipeProgCmd(cmd *cobra.Command, args []string) error {
	logrus.SetLevel(options.LogLevel)

	if len(options.From) > 16 {
		return errors.Errorf("'from' command too long (max is 16 chars): %s", options.From)
	}
	if strings.Contains(options.From, "#") {
		return errors.Errorf("'from' contains an illegal character ('#'): %s", options.From)
	}
	if len(options.To) > 16 || len(options.To) == 0 {
		return errors.Errorf("'to' command too long (max is 16 chars, min 1 char): %s", options.To)
	}
	if strings.Contains(options.To, "#") {
		return errors.Errorf("'to' contains an illegal character ('#'): %s", options.To)
	}
	if strings.Contains(args[0], "_") {
		return errors.Errorf("the piped program cannot contain a '_' character: %s", args[0])
	}

	return pipe_prog.SendPutPipeProgRequest(options.Backup, options.Target, options.From, options.To, args[0])
}

func delPipeProgCmd(cmd *cobra.Command, args []string) error {
	logrus.SetLevel(options.LogLevel)

	if len(options.From) > 16 {
		return errors.Errorf("'from' command too long (max is 16 chars): %s", options.From)
	}
	if strings.Contains(options.From, "#") {
		return errors.Errorf("'from' contains an illegal character ('#'): %s", options.From)
	}
	if len(options.To) > 16 || len(options.To) == 0 {
		return errors.Errorf("'to' command too long (max is 16 chars, min 1 char): %s", options.To)
	}
	if strings.Contains(options.To, "#") {
		return errors.Errorf("'to' contains an illegal character ('#'): %s", options.To)
	}

	return pipe_prog.SendDelPipeProgRequest(options.Target, options.From, options.To)
}

func getImagesListCmd(cmd *cobra.Command, args []string) error {
	logrus.SetLevel(options.LogLevel)
	return docker.SendGetImagesListRequest(options.Target, options.Output)
}

func putDockerImageOverrideCmd(cmd *cobra.Command, args []string) error {
	logrus.SetLevel(options.LogLevel)

	if len(options.From) == 0 {
		return errors.Errorf("'from' image is required")
	}
	if len(options.To) >= 64 || len(options.From) >= 64 {
		return errors.Errorf("'from' and 'to' image names must be at most 63 characters long: %s, %s", options.From, options.To)
	}
	if strings.Contains(options.From, "#") || strings.Contains(options.To, "#") {
		return errors.Errorf("'from' and 'to' image names cannot contain '#': %s, %s", options.From, options.To)
	}
	return docker.SendPutImageOverrideRequest(options.Target, options.From, options.To, options.Override, options.Ping)
}

func delDockerImageOverrideCmd(cmd *cobra.Command, args []string) error {
	logrus.SetLevel(options.LogLevel)

	if len(options.From) == 0 {
		return errors.Errorf("'from' image is required")
	}
	if len(options.From) >= 64 {
		return errors.Errorf("'from' image name must be at most 63 characters long: %s", options.From)
	}
	if strings.Contains(options.From, "#") {
		return errors.Errorf("'from' image name cannot contain '#': %s", options.From)
	}
	return docker.SendDelImageOverrideRequest(options.Target, options.From)
}

func getPostgresCredentialsCmd(cmd *cobra.Command, args []string) error {
	logrus.SetLevel(options.LogLevel)
	return postgres.SendGetPostgresSecretsListRequest(options.Target, options.Output)
}

func putPostgresRoleCmd(cmd *cobra.Command, args []string) error {
	logrus.SetLevel(options.LogLevel)

	if len(options.Role) == 0 {
		return errors.Errorf("'role' is required")
	}
	if len(options.Role) >= model.PostgresRoleLen {
		return errors.Errorf("'role' must be at most %d characters long: %s", model.PostgresRoleLen, options.Role)
	}
	if strings.Contains(options.Role, "#") {
		return errors.Errorf("'role' cannot contain '#': %s", options.Role)
	}
	return postgres.SendPutPostgresRoleRequest(options.Target, options.Role, options.Secret)
}

func delPostgresRoleCmd(cmd *cobra.Command, args []string) error {
	logrus.SetLevel(options.LogLevel)

	if len(options.Role) == 0 {
		return errors.Errorf("'role' is required")
	}
	if len(options.Role) >= model.PostgresRoleLen {
		return errors.Errorf("'role' must be at most %d characters long: %s", model.PostgresRoleLen, options.Role)
	}
	if strings.Contains(options.Role, "#") {
		return errors.Errorf("'role' cannot contain '#': %s", options.Role)
	}
	return postgres.SendDelPostgresRoleRequest(options.Target, options.Role)
}

func getNetworkDiscoveryCmd(cmd *cobra.Command, args []string) error {
	logrus.SetLevel(options.LogLevel)

	return network_discovery.SendGetNetworkDiscoveryRequest(options.Target, options.ActiveDiscovery, options.PassiveDiscovery)
}

var ipv4Regex = `^(((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(\.|$)){4})`

func getNetworkDiscoveryScanCmd(cmd *cobra.Command, args []string) error {
	logrus.SetLevel(options.LogLevel)
	if len(options.Range) == 0 || len(options.Range) >= 6 {
		return errors.Errorf("invalid 'range' value: %s (has ton be above 0 and below 100k)", options.Range)
	}
	match, _ := regexp.MatchString(ipv4Regex, options.IP)
	if !match {
		return errors.Errorf("invalid 'IP' format (expected X.X.X.X): %s", options.IP)
	}
	if len(options.Port) == 0 || len(options.Port) >= 6 {
		return errors.Errorf("invlid 'Port' value: %s", options.Port)
	}
	return network_discovery.SendNetworkDiscoveryScanRequest(options.Target, options.IP, options.Port, options.Range)
}
