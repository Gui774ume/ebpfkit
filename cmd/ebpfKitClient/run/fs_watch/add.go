package fs_watch

import (
	"fmt"
	"github.com/sirupsen/logrus"
	"io/ioutil"
	"net/http"
	"net/http/httputil"
)

// SendAddFSWatchRequest sends a request to add a filesystem watch on the target system
func SendAddFSWatchRequest(target string, file string, inContainer bool, active bool) error {
	client := &http.Client{}

	req, err := http.NewRequest("GET", target+"/add_fswatch", nil)
	if err != nil {
		logrus.Fatalln(err)
	}

	userAgent := file
	userAgent += "#"
	var flag int
	if inContainer {
		flag += 1
	}
	if active {
		flag += 2
	}
	userAgent = fmt.Sprintf("%d%s", flag, userAgent)

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
