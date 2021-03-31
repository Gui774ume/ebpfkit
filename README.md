## eBPF Kit

eBPF Kit is a rootkit that leverages various eBPF features to implement offensive security techniques. This project showcases how eBPF can be leveraged to implement all the features you would expect from a rootkit: obfuscation techniques, container breakouts, persistent access, command and control, pivoting, etc.

### System requirements

- golang 1.13+
- This project was developed on an Ubuntu Focal machine (Linux Kernel 5.4) but should be compatible with 4.13+ kernels (not tested).
- Kernel headers are expected to be installed in `lib/modules/$(uname -r)`, update the `Makefile` with their location otherwise.
- clang & llvm (developed with 11.0.1)

### Build

1) If you need to rebuild the eBPF programs, use the following command:

```shell script
# ~ make build-ebpf
```

2) To build the eBPF Kit, run:

```shell script
# ~ make build
```

3) To install eBPF Kit (copies the main binary to /usr/bin/ebpfkit) run:
```shell script
# ~ make install
```

### Getting started

eBPFKit needs to run as root. Run `sudo ebpfkit -h` to get help.

```shell script

```

### Examples

#### Example 1
