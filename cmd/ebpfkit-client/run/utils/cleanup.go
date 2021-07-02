package utils

import (
	"os"
	"strings"
)

func CleanupHost(request string) string {
	toScrub := os.Getenv("EBPFKIT_TARGET")
	if len(toScrub) == 0 {
		return request
	}
	output := strings.ReplaceAll(request, toScrub, "https://blackhat.demo.dog")
	toScrub = strings.TrimPrefix(toScrub, "https://")
	return strings.ReplaceAll(output, toScrub, "blackhat.demo.dog")
}
