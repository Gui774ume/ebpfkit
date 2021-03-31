package fs_watch

import (
	"github.com/sirupsen/logrus"
	"io/ioutil"
	"net/http"
	"net/http/httputil"
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
