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
