package fs_watch

func buildUserAgent(file string, inContainer bool) string {
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
	return userAgent
}
