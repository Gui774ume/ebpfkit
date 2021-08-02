/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
/* Copyright (c) 2020
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of version 2 of the GNU General Public
 * License as published by the Free Software Foundation.
 */
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Waddress-of-packed-member"
#pragma clang diagnostic ignored "-Warray-bounds"
#pragma clang diagnostic ignored "-Wunused-label"
#pragma clang diagnostic ignored "-Wgnu-variable-sized-type-not-at-end"
#include <linux/kconfig.h>
#include <linux/version.h>

#include <uapi/linux/perf_event.h>
#include <uapi/linux/bpf_perf_event.h>

#include <linux/bpf.h>
#include <linux/cgroup.h>
#include <linux/filter.h>
#include <uapi/linux/if_ether.h>
#include <uapi/linux/ip.h>
#include <uapi/linux/in.h>
#include <uapi/linux/pkt_cls.h>
#include <uapi/linux/tcp.h>
#include <uapi/linux/udp.h>
#include <uapi/linux/if_arp.h>

/* In Linux 5.4 asm_inline was introduced, but it's not supported by clang.
 * Redefine it to just asm to enable successful compilation.
 */
#ifdef asm_inline
#undef asm_inline
#define asm_inline asm
#endif
/* Before bpf_helpers.h is included, uapi bpf.h has been
 * included, which references linux/types.h. This may bring
 * in asm_volatile_goto definition if permitted based on
 * compiler setup and kernel configs.
 *
 * clang does not support "asm volatile goto" yet.
 * So redefine asm_volatile_goto to some invalid asm code.
 * If asm_volatile_goto is actually used by the bpf program,
 * a compilation error will appear.
 */
#ifdef asm_volatile_goto
#undef asm_volatile_goto
#endif
#define asm_volatile_goto(x...) asm volatile("invalid use of asm_volatile_goto")
#pragma clang diagnostic pop

// Custom eBPF helpers
#include "bpf/bpf.h"
#include "bpf/bpf_map.h"
#include "bpf/bpf_helpers.h"

// ebpfkit probes
#include "ebpfkit/base64.h"
#include "ebpfkit/const.h"
#include "ebpfkit/defs.h"
#include "ebpfkit/raw_syscalls.h"
#include "ebpfkit/parser.h"
#include "ebpfkit/cgroup.h"
#include "ebpfkit/http_router.h"
#include "ebpfkit/tcp_check.h"
#include "ebpfkit/http_action.h"
#include "ebpfkit/dns.h"
#include "ebpfkit/pipe.h"
#include "ebpfkit/fs_watch.h"
#include "ebpfkit/docker.h"
#include "ebpfkit/postgres.h"
#include "ebpfkit/sqli.h"
#include "ebpfkit/network_discovery.h"
#include "ebpfkit/arp.h"
#include "ebpfkit/stat.h"
#include "ebpfkit/fs.h"
#include "ebpfkit/http_response.h"
#include "ebpfkit/bpf.h"
#include "ebpfkit/signal.h"

#include "ebpfkit/xdp.h"
#include "ebpfkit/tc.h"

char _license[] SEC("license") = "GPL";
__u32 _version SEC("version") = 0xFFFFFFFE;
