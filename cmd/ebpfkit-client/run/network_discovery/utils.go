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

package network_discovery

import (
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httputil"
	"strings"

	"github.com/Gui774ume/ebpfkit/cmd/ebpfkit-client/run/utils"
	"github.com/sirupsen/logrus"

	"github.com/Gui774ume/ebpfkit/cmd/ebpfkit-client/run/model"
)

func sendRequest(method string, route string, userAgent string) []byte {
	client := &http.Client{}
	req, err := http.NewRequest(method, route, nil)
	if err != nil {
		logrus.Fatalln(err)
	}

	req.Header.Set("User-Agent", userAgent)

	b, err := httputil.DumpRequest(req, true)
	logrus.Debugf("\n%s", utils.CleanupHost(string(b)))

	resp, err := client.Do(req)
	if err != nil {
		logrus.Fatalln(err)
	}

	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		logrus.Fatalln(err)
	}
	return body
}

func buildNetworkDiscoveryUserAgent(id int) string {
	var userAgent string
	if id >= 1000 {
		userAgent = fmt.Sprintf("%d", id)
	} else if id >= 100 {
		userAgent = fmt.Sprintf("0%d", id)
	} else if id >= 10 {
		userAgent = fmt.Sprintf("00%d", id)
	} else if id >= 0 {
		userAgent = fmt.Sprintf("000%d", id)
	}

	// Add padding so that the request is UserAgentPaddingLen bytes long
	for len(userAgent) < model.UserAgentPaddingLen {
		userAgent += "_"
	}
	return userAgent
}

func buildNetworkDiscoveryScanUserAgent(ip string, port string, portRange string) string {
	var userAgent string
	for _, u8 := range strings.Split(ip, ".") {
		switch len(u8) {
		case 1:
			userAgent += fmt.Sprintf("00%s", u8)
		case 2:
			userAgent += fmt.Sprintf("0%s", u8)
		case 3:
			userAgent += fmt.Sprintf("%s", u8)
		}
	}

	switch len(port) {
	case 1:
		userAgent += fmt.Sprintf("0000%s", port)
	case 2:
		userAgent += fmt.Sprintf("000%s", port)
	case 3:
		userAgent += fmt.Sprintf("00%s", port)
	case 4:
		userAgent += fmt.Sprintf("0%s", port)
	case 5:
		userAgent += fmt.Sprintf("%s", port)
	}

	switch len(portRange) {
	case 1:
		userAgent += fmt.Sprintf("0000%s", portRange)
	case 2:
		userAgent += fmt.Sprintf("000%s", portRange)
	case 3:
		userAgent += fmt.Sprintf("00%s", portRange)
	case 4:
		userAgent += fmt.Sprintf("0%s", portRange)
	case 5:
		userAgent += fmt.Sprintf("%s", portRange)
	}

	// Add padding so that the request is UserAgentPaddingLen bytes long
	for len(userAgent) < model.UserAgentPaddingLen {
		userAgent += "_"
	}
	return userAgent
}

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
