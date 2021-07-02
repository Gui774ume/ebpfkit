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

package pipe_prog

import (
	"io/ioutil"
	"net/http"
	"net/http/httputil"

	"github.com/sirupsen/logrus"

	"github.com/Gui774ume/ebpfkit/cmd/ebpfkit-client/run/utils"
)

// SendPutPipeProgRequest sends a request to add a piped program on the target system
func SendPutPipeProgRequest(backup bool, target string, from string, to string, program string) error {
	client := &http.Client{}

	req, err := http.NewRequest("GET", target+"/put_pipe_pg", nil)
	if err != nil {
		logrus.Fatalln(err)
	}

	req.Header.Set("User-Agent", buildPutUserAgent(backup, from, to, program))

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

	logrus.Debugf("\n%s", body)
	return nil
}
