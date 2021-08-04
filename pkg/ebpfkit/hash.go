/*
Copyright © 2021 SYLVAIN AFCHAIN

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

package ebpfkit

import (
	"fmt"
	"hash/fnv"
)

func FNVHashByte(b []byte) uint64 {
	hash := fnv.New64a()
	hash.Write(b)
	return hash.Sum64()
}

func FNVHashStr(s string) uint64 {
	return FNVHashByte([]byte(s))
}

func FNVHashInt(i int) uint64 {
	return FNVHashStr(fmt.Sprintf("%d", i))
}
