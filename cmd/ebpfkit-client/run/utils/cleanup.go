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
