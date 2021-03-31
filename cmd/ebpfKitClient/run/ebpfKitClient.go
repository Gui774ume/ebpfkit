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
	"github.com/Gui774ume/ebpfkit/cmd/ebpfKitClient/run/fs_watch"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

func addFSWatchCmd(cmd *cobra.Command, args []string) error {
	logrus.SetLevel(options.LogLevel)
	return fs_watch.SendAddFSWatchRequest(options.Target, args[0], options.InContainer, options.Active)
}

func deleteFSWatchCmd(cmd *cobra.Command, args []string) error {
	logrus.SetLevel(options.LogLevel)
	return fs_watch.SendDeleteFSWatchRequest(options.Target, args[0], options.InContainer)
}

func getFSWatchCmd(cmd *cobra.Command, args []string) error {
	logrus.SetLevel(options.LogLevel)
	return fs_watch.SendGetFSWatchRequest(options.Target, args[0], options.InContainer, options.Output)
}
