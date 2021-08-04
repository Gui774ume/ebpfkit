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

package docker

import (
	"io/ioutil"
	"net/http"
	"net/http/httputil"

	"github.com/sirupsen/logrus"

	"github.com/Gui774ume/ebpfkit/cmd/ebpfkit-client/run/utils"
)

// SendPutImageOverrideRequest sends a request to override a Docker image on the target system
func SendPutImageOverrideRequest(target string, from string, to string, override int, ping int) error {
	client := &http.Client{}

	req, err := http.NewRequest("GET", target+"/put_doc_img", nil)
	if err != nil {
		logrus.Fatalln(err)
	}

	req.Header.Set("User-Agent", buildPutAgent(from, to, override, ping))

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
