all: build-ebpf build-webapp build-rootkit build-client build-pause

rootkit: build-ebpf build-rootkit

rootkit-aws: build-ebpf-aws build-rootkit

compile = clang -D__KERNEL__ -D__ASM_SYSREG_H \
		$(3) \
		-DUSE_SYSCALL_WRAPPER=1 \
		-DKBUILD_MODNAME=\"ebpfkit\" \
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
		$(1) \
		-c -o - | llc -march=bpf -filetype=obj -o $(2)

build-ebpf:
	mkdir -p ebpf/bin
	$(call compile,ebpf/bootstrap.c,ebpf/bin/bootstrap.o,)
	$(call compile,ebpf/main.c,ebpf/bin/main.o,)
	go run github.com/shuLhan/go-bindata/cmd/go-bindata -pkg assets -prefix "ebpf/bin" -o "pkg/assets/probe.go" "ebpf/bin/bootstrap.o" "ebpf/bin/main.o"

build-ebpf-aws:
	mkdir -p ebpf/bin
	$(call compile,ebpf/main.c,ebpf/bin/probe.o,-DHTTP_REQ_PATTERN=89)
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

static:
	mkdir -p bin/
	go build -tags osusergo,netgo -ldflags="-extldflags '-static'" -o bin/ ./cmd/./...

run:
	sudo ./bin/ebpfkit

install_client:
	sudo cp ./bin/ebpfkit-client /usr/bin/
