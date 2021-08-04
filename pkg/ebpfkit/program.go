/*
Copyright © 2021 Sylvain Baubeau

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
	"unsafe"

	"golang.org/x/sys/unix"
)

/*
        struct { anonymous struct used by BPF_*_GET_*_ID
			union {
				__u32           start_id;
				__u32           prog_id;
				__u32           map_id;
				__u32           btf_id;
				__u32           link_id;
		};
		__u32           next_id;
		__u32           open_flags;
};
*/

type bpfGetId struct {
	ID        uint32
	NextID    uint32
	OpenFlags uint32
}

func ProgGetNextId(prev int) (int, error) {
	bgi := bpfGetId{ID: uint32(prev)}

	ret, _, _ := unix.Syscall(
		unix.SYS_BPF,
		unix.BPF_PROG_GET_NEXT_ID,
		uintptr(unsafe.Pointer(&bgi)),
		unsafe.Sizeof(bgi),
	)

	if ret != 0 {
		return int(ret), nil
	}

	return int(bgi.NextID), nil
}
