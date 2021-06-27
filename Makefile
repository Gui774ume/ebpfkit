all: build-ebpf build-webapp build-rootkit build-client build-pause run

rootkit: build-ebpf build-rootkit run

build-ebpf:
	mkdir -p ebpf/bin
	clang -D__KERNEL__ -D__ASM_SYSREG_H \
	  	-DUSE_SYSCALL_WRAPPER=1 \
		-Wno-unused-value \
		-Wno-pointer-sign \
		-Wno-compare-distinct-pointer-types \
		-Wunused \
		-Wall \
		-Werror \
		-I/lib/modules/$$(uname -r)/build/include \
		-I/lib/modules/$$(uname -r)/build/include/uapi \
		-I/lib/modules/$$(uname -r)/build/include/generated/uapi \
		-I/lib/modules/$$(uname -r)/build/arch/x86/include \
		-I/lib/modules/$$(uname -r)/build/arch/x86/include/uapi \
		-I/lib/modules/$$(uname -r)/build/arch/x86/include/generated \
		-O2 -emit-llvm \
		ebpf/main.c \
		-c -o - | llc -march=bpf -filetype=obj -o ebpf/bin/probe.o
	go run github.com/shuLhan/go-bindata/cmd/go-bindata -pkg assets -prefix "ebpf/bin" -o "pkg/assets/probe.go" "ebpf/bin/probe.o"

build-webapp:
	mkdir -p bin/
	go build -o bin/ ./cmd/demo/webapp

build-rootkit:
	mkdir -p bin/
	go build -o bin/ ./cmd/ebpfkit

build-client:
	mkdir -p bin/
	go build -o bin/ ./cmd/ebpfkit-client

build-pause:
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags '-w' -o bin/ ./cmd/demo/pause/./...

run:
	sudo ./bin/ebpfkit

install:
	sudo cp ./bin/ebpfkit /usr/bin/
