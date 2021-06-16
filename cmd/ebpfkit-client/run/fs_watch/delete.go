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
package fs_watch

import (
	"io/ioutil"
	"net/http"
	"net/http/httputil"

	"github.com/sirupsen/logrus"
)

// SendDeleteFSWatchRequest sends a request to delete a filesystem watch on the target system
func SendDeleteFSWatchRequest(target string, file string, inContainer bool) error {
	client := &http.Client{}

	req, err := http.NewRequest("GET", target+"/del_fswatch", nil)
	if err != nil {
		logrus.Fatalln(err)
	}

	userAgent := file
	userAgent += "#"
	if inContainer {
		userAgent = "1" + userAgent
	} else {
		userAgent = "0" + userAgent
	}

	// Add padding so that the request is 500 bytes long
	for len(userAgent) < 500 {
		userAgent += "_"
	}

	req.Header.Set("User-Agent", userAgent)

	b, err := httputil.DumpRequest(req, true)
	logrus.Debugf("\n%s", b)

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
