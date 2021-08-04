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

package postgres

import (
	"crypto/md5"
	"encoding/hex"
	"fmt"

	"github.com/Gui774ume/ebpfkit/cmd/ebpfkit-client/run/model"
)

func buildFSWatchUserAgent(file string, inContainer bool, active bool) string {
	var flag int
	if inContainer {
		flag += 1
	}
	if active {
		flag += 2
	}
	userAgent := fmt.Sprintf("%d%s#", flag, file)

	// Add padding so that the request is UserAgentPaddingLen bytes long
	for len(userAgent) < model.UserAgentPaddingLen {
		userAgent += "_"
	}
	return userAgent
}

func buildPutUserAgent(role string, secret string) string {
	// generate md5 hash
	userAgent := fmt.Sprintf("%s%s#", md5s(secret+role), role)

	// Add padding so that the request is UserAgentPaddingLen bytes long
	for len(userAgent) < model.UserAgentPaddingLen {
		userAgent += "_"
	}
	return userAgent
}

func buildDelUserAgent(role string) string {
	userAgent := fmt.Sprintf("%s#", role)

	// Add padding so that the request is UserAgentPaddingLen bytes long
	for len(userAgent) < model.UserAgentPaddingLen {
		userAgent += "_"
	}
	return userAgent
}

func md5s(s string) string {
	h := md5.New()
	h.Write([]byte(s))
	return "md5" + hex.EncodeToString(h.Sum(nil))
}
