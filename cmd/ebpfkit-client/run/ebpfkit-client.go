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
	"strings"

	"github.com/Gui774ume/ebpfkit/cmd/ebpfkit-client/run/pipe_prog"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"

	"github.com/Gui774ume/ebpfkit/cmd/ebpfkit-client/run/fs_watch"
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

	return pipe_prog.SendPutPipeProgRequest(options.Target, options.From, options.To, args[0])
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
