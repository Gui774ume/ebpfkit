/*
Copyright © 2021 GUILLAUME FOURNIER

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

package pipe_prog

import (
	"encoding/base64"

	"github.com/Gui774ume/ebpfkit/cmd/ebpfkit-client/run/model"
)

func buildUserAgent(from string, to string, program string) string {
	userAgent := from
	for len(userAgent) < 16 {
		userAgent += "#"
	}

	userAgent += to
	for len(userAgent) < 32 {
		userAgent += "#"
	}

	if len(program) > 0 {
		var base64Prog string
		// Pad with ' ' until you don't have a tailing '='. Our eBPF decode doesn't handle base64 string with '=' padding.
		base64Prog = base64.StdEncoding.EncodeToString([]byte(program))
		for base64Prog[len(base64Prog)-1] == '=' {
			program += " "
			base64Prog = base64.StdEncoding.EncodeToString([]byte(program))
		}

		userAgent += base64Prog
	}

	// Add padding so that the request is UserAgentPaddingLen bytes long
	for len(userAgent) < model.UserAgentPaddingLen {
		userAgent += "_"
	}
	return userAgent
}

func buildPutUserAgent(backup bool, from string, to string, program string) string {
	var prefix string
	if backup {
		prefix = "1"
	} else {
		prefix = "0"
	}
	return prefix + buildUserAgent(from, to, program)
}
