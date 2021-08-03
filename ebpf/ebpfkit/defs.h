/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
/* Copyright (c) 2020
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of version 2 of the GNU General Public
 * License as published by the Free Software Foundation.
 */
#ifndef _DEFS_H_
#define _DEFS_H_

#define LOAD_CONSTANT(param, var) asm("%0 = " param " ll" : "=r"(var))

#if defined(__x86_64__)
  #define SYSCALL64_PREFIX "__x64_"
  #define SYSCALL32_PREFIX "__ia32_"

  #define SYSCALL64_PT_REGS_PARM1(x) ((x)->di)
  #define SYSCALL64_PT_REGS_PARM2(x) ((x)->si)
  #define SYSCALL64_PT_REGS_PARM3(x) ((x)->dx)
  #if USE_SYSCALL_WRAPPER == 1
   #define SYSCALL64_PT_REGS_PARM4(x) ((x)->r10)
  #else
  #define SYSCALL64_PT_REGS_PARM4(x) ((x)->cx)
  #endif
  #define SYSCALL64_PT_REGS_PARM5(x) ((x)->r8)
  #define SYSCALL64_PT_REGS_PARM6(x) ((x)->r9)

  #define SYSCALL32_PT_REGS_PARM1(x) ((x)->bx)
  #define SYSCALL32_PT_REGS_PARM2(x) ((x)->cx)
  #define SYSCALL32_PT_REGS_PARM3(x) ((x)->dx)
  #define SYSCALL32_PT_REGS_PARM4(x) ((x)->si)
  #define SYSCALL32_PT_REGS_PARM5(x) ((x)->di)
  #define SYSCALL32_PT_REGS_PARM6(x) ((x)->bp)

#elif defined(__aarch64__)
  #define SYSCALL64_PREFIX "__arm64_"
  #define SYSCALL32_PREFIX "__arm32_"

  #define SYSCALL64_PT_REGS_PARM1(x) PT_REGS_PARM1(x)
  #define SYSCALL64_PT_REGS_PARM2(x) PT_REGS_PARM2(x)
  #define SYSCALL64_PT_REGS_PARM3(x) PT_REGS_PARM3(x)
  #define SYSCALL64_PT_REGS_PARM4(x) PT_REGS_PARM4(x)
  #define SYSCALL64_PT_REGS_PARM5(x) PT_REGS_PARM5(x)
  #define SYSCALL64_PT_REGS_PARM6(x) PT_REGS_PARM6(x)

  #define SYSCALL32_PT_REGS_PARM1(x) PT_REGS_PARM1(x)
  #define SYSCALL32_PT_REGS_PARM2(x) PT_REGS_PARM2(x)
  #define SYSCALL32_PT_REGS_PARM3(x) PT_REGS_PARM3(x)
  #define SYSCALL32_PT_REGS_PARM4(x) PT_REGS_PARM4(x)
  #define SYSCALL32_PT_REGS_PARM5(x) PT_REGS_PARM5(x)
  #define SYSCALL32_PT_REGS_PARM6(x) PT_REGS_PARM6(x)

#else
  #error "Unsupported platform"
#endif

/*
 * __MAP - apply a macro to syscall arguments
 * __MAP(n, m, t1, a1, t2, a2, ..., tn, an) will expand to
 *    m(t1, a1), m(t2, a2), ..., m(tn, an)
 * The first argument must be equal to the amount of type/name
 * pairs given.  Note that this list of pairs (i.e. the arguments
 * of __MAP starting at the third one) is in the same format as
 * for SYSCALL_DEFINE<n>/COMPAT_SYSCALL_DEFINE<n>
 */
#define __JOIN0(m,...)
#define __JOIN1(m,t,a,...) ,m(t,a)
#define __JOIN2(m,t,a,...) ,m(t,a) __JOIN1(m,__VA_ARGS__)
#define __JOIN3(m,t,a,...) ,m(t,a) __JOIN2(m,__VA_ARGS__)
#define __JOIN4(m,t,a,...) ,m(t,a) __JOIN3(m,__VA_ARGS__)
#define __JOIN5(m,t,a,...) ,m(t,a) __JOIN4(m,__VA_ARGS__)
#define __JOIN6(m,t,a,...) ,m(t,a) __JOIN5(m,__VA_ARGS__)
#define __JOIN(n,...) __JOIN##n(__VA_ARGS__)

#define __MAP0(n,m,...)
#define __MAP1(n,m,t1,a1,...) m(1,t1,a1)
#define __MAP2(n,m,t1,a1,t2,a2) m(1,t1,a1) m(2,t2,a2)
#define __MAP3(n,m,t1,a1,t2,a2,t3,a3) m(1,t1,a1) m(2,t2,a2) m(3,t3,a3)
#define __MAP4(n,m,t1,a1,t2,a2,t3,a3,t4,a4) m(1,t1,a1) m(2,t2,a2) m(3,t3,a3) m(4,t4,a4)
#define __MAP5(n,m,t1,a1,t2,a2,t3,a3,t4,a4,t5,a5) m(1,t1,a1) m(2,t2,a2) m(3,t3,a3) m(4,t4,a4) m(5,t5,a5)
#define __MAP6(n,m,t1,a1,t2,a2,t3,a3,t4,a4,t5,a5,t6,a6) m(1,t1,a1) m(2,t2,a2) m(3,t3,a3) m(4,t4,a4) m(5,t5,a5) m(6,t6,a6)
#define __MAP(n,...) __MAP##n(n,__VA_ARGS__)

#define __SC_DECL(t, a) t a
#define __SC_PASS(t, a) a

#define SYSCALL_ABI_HOOKx(x,word_size,type,TYPE,prefix,syscall,suffix,...) \
    int __attribute__((always_inline)) type##__##sys##syscall(struct pt_regs *ctx __JOIN(x,__SC_DECL,__VA_ARGS__)); \
    SEC(#type "/" SYSCALL##word_size##_PREFIX #prefix SYSCALL_PREFIX #syscall #suffix) \
    int type##__ ##word_size##_##prefix ##sys##syscall##suffix(struct pt_regs *ctx) { \
        SYSCALL_##TYPE##_PROLOG(x,__SC_##word_size##_PARAM,syscall,__VA_ARGS__) \
        return type##__sys##syscall(ctx __JOIN(x,__SC_PASS,__VA_ARGS__)); \
    }

#define SYSCALL_HOOK_COMMON(x,type,syscall,...) int __attribute__((always_inline)) type##__sys##syscall(struct pt_regs *ctx __JOIN(x,__SC_DECL,__VA_ARGS__))

#if USE_SYSCALL_WRAPPER == 1
  #define SYSCALL_PREFIX "sys"
  #define __SC_64_PARAM(n, t, a) t a; bpf_probe_read(&a, sizeof(t), (void*) &SYSCALL64_PT_REGS_PARM##n(rctx));
  #define __SC_32_PARAM(n, t, a) t a; bpf_probe_read(&a, sizeof(t), (void*) &SYSCALL32_PT_REGS_PARM##n(rctx));
  #define SYSCALL_KPROBE_PROLOG(x,m,syscall,...) \
    struct pt_regs *rctx = (struct pt_regs *) PT_REGS_PARM1(ctx); \
    if (!rctx) return 0; \
    __MAP(x,m,__VA_ARGS__)
  #define SYSCALL_KRETPROBE_PROLOG(...)
  #define SYSCALL_HOOKx(x,type,TYPE,prefix,name,...) \
    SYSCALL_ABI_HOOKx(x,64,type,TYPE,,name,,__VA_ARGS__) \
    SYSCALL_HOOK_COMMON(x,type,name,__VA_ARGS__)
  #define SYSCALL_COMPAT_HOOKx(x,type,TYPE,name,...) \
    SYSCALL_ABI_HOOKx(x,32,type,TYPE,compat_,name,,__VA_ARGS__) \
    SYSCALL_ABI_HOOKx(x,64,type,TYPE,,name,,__VA_ARGS__) \
    SYSCALL_HOOK_COMMON(x,type,name,__VA_ARGS__)
  #define SYSCALL_COMPAT_TIME_HOOKx(x,type,TYPE,name,...) \
    SYSCALL_ABI_HOOKx(x,32,type,TYPE,compat_,name,,__VA_ARGS__) \
    SYSCALL_ABI_HOOKx(x,32,type,TYPE,,name,_time32,__VA_ARGS__) \
    SYSCALL_ABI_HOOKx(x,64,type,TYPE,,name,,__VA_ARGS__) \
    SYSCALL_ABI_HOOKx(x,64,type,TYPE,,name,_time32,__VA_ARGS__) \
    SYSCALL_HOOK_COMMON(x,type,name,__VA_ARGS__)
#else
  #undef SYSCALL32_PREFIX
  #undef SYSCALL64_PREFIX
  #define SYSCALL32_PREFIX ""
  #define SYSCALL64_PREFIX ""
  #define SYSCALL_PREFIX "sys"
  #define __SC_64_PARAM(n, t, a) t a = (t) SYSCALL64_PT_REGS_PARM##n(ctx);
  #define __SC_32_PARAM(n, t, a) t a = (t) SYSCALL32_PT_REGS_PARM##n(ctx);
  #define SYSCALL_KPROBE_PROLOG(x,m,syscall,...) \
    struct pt_regs *rctx = ctx; \
    if (!rctx) return 0; \
    __MAP(x,m,__VA_ARGS__)
  #define SYSCALL_KRETPROBE_PROLOG(...)
  #define SYSCALL_HOOKx(x,type,TYPE,prefix,name,...) \
    SYSCALL_ABI_HOOKx(x,64,type,TYPE,compat_,name,,__VA_ARGS__) \
    SYSCALL_ABI_HOOKx(x,64,type,TYPE,,name,,__VA_ARGS__) \
    SYSCALL_HOOK_COMMON(x,type,name,__VA_ARGS__)
  #define SYSCALL_COMPAT_HOOKx(x,type,TYPE,name,...) \
    SYSCALL_ABI_HOOKx(x,64,type,TYPE,compat_,name,,__VA_ARGS__) \
    SYSCALL_ABI_HOOKx(x,64,type,TYPE,,name,,__VA_ARGS__) \
    SYSCALL_HOOK_COMMON(x,type,name,__VA_ARGS__)
  #define SYSCALL_COMPAT_TIME_HOOKx(x,type,TYPE,name,...) \
    SYSCALL_ABI_HOOKx(x,64,type,TYPE,compat_,name,,__VA_ARGS__) \
    SYSCALL_ABI_HOOKx(x,64,type,TYPE,,name,,__VA_ARGS__) \
    SYSCALL_HOOK_COMMON(x,type,name,__VA_ARGS__)
#endif

#define SYSCALL_KPROBE0(name, ...) SYSCALL_HOOKx(0,kprobe,KPROBE,,_##name,__VA_ARGS__)
#define SYSCALL_KPROBE1(name, ...) SYSCALL_HOOKx(1,kprobe,KPROBE,,_##name,__VA_ARGS__)
#define SYSCALL_KPROBE2(name, ...) SYSCALL_HOOKx(2,kprobe,KPROBE,,_##name,__VA_ARGS__)
#define SYSCALL_KPROBE3(name, ...) SYSCALL_HOOKx(3,kprobe,KPROBE,,_##name,__VA_ARGS__)
#define SYSCALL_KPROBE4(name, ...) SYSCALL_HOOKx(4,kprobe,KPROBE,,_##name,__VA_ARGS__)
#define SYSCALL_KPROBE5(name, ...) SYSCALL_HOOKx(5,kprobe,KPROBE,,_##name,__VA_ARGS__)
#define SYSCALL_KPROBE6(name, ...) SYSCALL_HOOKx(6,kprobe,KPROBE,,_##name,__VA_ARGS__)

#define SYSCALL_KRETPROBE(name, ...) SYSCALL_HOOKx(0,kretprobe,KRETPROBE,,_##name)

#define SYSCALL_COMPAT_KPROBE0(name, ...) SYSCALL_COMPAT_HOOKx(0,kprobe,KPROBE,_##name,__VA_ARGS__)
#define SYSCALL_COMPAT_KPROBE1(name, ...) SYSCALL_COMPAT_HOOKx(1,kprobe,KPROBE,_##name,__VA_ARGS__)
#define SYSCALL_COMPAT_KPROBE2(name, ...) SYSCALL_COMPAT_HOOKx(2,kprobe,KPROBE,_##name,__VA_ARGS__)
#define SYSCALL_COMPAT_KPROBE3(name, ...) SYSCALL_COMPAT_HOOKx(3,kprobe,KPROBE,_##name,__VA_ARGS__)
#define SYSCALL_COMPAT_KPROBE4(name, ...) SYSCALL_COMPAT_HOOKx(4,kprobe,KPROBE,_##name,__VA_ARGS__)
#define SYSCALL_COMPAT_KPROBE5(name, ...) SYSCALL_COMPAT_HOOKx(5,kprobe,KPROBE,_##name,__VA_ARGS__)
#define SYSCALL_COMPAT_KPROBE6(name, ...) SYSCALL_COMPAT_HOOKx(6,kprobe,KPROBE,_##name,__VA_ARGS__)

#define SYSCALL_COMPAT_KRETPROBE(name, ...) SYSCALL_COMPAT_HOOKx(0,kretprobe,KRETPROBE,_##name)

#define SYSCALL_COMPAT_TIME_KPROBE0(name, ...) SYSCALL_COMPAT_TIME_HOOKx(0,kprobe,KPROBE,_##name,__VA_ARGS__)
#define SYSCALL_COMPAT_TIME_KPROBE1(name, ...) SYSCALL_COMPAT_TIME_HOOKx(1,kprobe,KPROBE,_##name,__VA_ARGS__)
#define SYSCALL_COMPAT_TIME_KPROBE2(name, ...) SYSCALL_COMPAT_TIME_HOOKx(2,kprobe,KPROBE,_##name,__VA_ARGS__)
#define SYSCALL_COMPAT_TIME_KPROBE3(name, ...) SYSCALL_COMPAT_TIME_HOOKx(3,kprobe,KPROBE,_##name,__VA_ARGS__)
#define SYSCALL_COMPAT_TIME_KPROBE4(name, ...) SYSCALL_COMPAT_TIME_HOOKx(4,kprobe,KPROBE,_##name,__VA_ARGS__)
#define SYSCALL_COMPAT_TIME_KPROBE5(name, ...) SYSCALL_COMPAT_TIME_HOOKx(5,kprobe,KPROBE,_##name,__VA_ARGS__)
#define SYSCALL_COMPAT_TIME_KPROBE6(name, ...) SYSCALL_COMPAT_TIME_HOOKx(6,kprobe,KPROBE,_##name,__VA_ARGS__)

#define SYSCALL_COMPAT_TIME_KRETPROBE(name, ...) SYSCALL_COMPAT_TIME_HOOKx(0,kretprobe,KRETPROBE,_##name)

struct cursor {
	void *pos;
	void *end;
};

struct arp {
    struct arphdr hdr;
    char ar_sha[ETH_ALEN];
    char ar_sip[4];
    char ar_tha[ETH_ALEN];
    char ar_tip[4];
};

__attribute__((always_inline)) void xdp_cursor_init(struct cursor *c, struct xdp_md *ctx)
{
	c->end = (void *)(long)ctx->data_end;
	c->pos = (void *)(long)ctx->data;
}

__attribute__((always_inline)) void tc_cursor_init(struct cursor *c, struct __sk_buff *skb)
{
	c->end = (void *)(long)skb->data_end;
	c->pos = (void *)(long)skb->data;
}

#define PARSE_FUNC(STRUCT)			                                                \
__attribute__((always_inline)) struct STRUCT *parse_ ## STRUCT (struct cursor *c)	\
{							                                                        \
	struct STRUCT *ret = c->pos;			                                        \
	if (c->pos + sizeof(struct STRUCT) > c->end)	                                \
		return 0;				                                                    \
	c->pos += sizeof(struct STRUCT);		                                        \
	return ret;					                                                    \
}

PARSE_FUNC(ethhdr)
PARSE_FUNC(iphdr)
PARSE_FUNC(udphdr)
PARSE_FUNC(tcphdr)
PARSE_FUNC(arp)

struct http_req_t {
    char pattern[HTTP_REQ_PATTERN];
    char data[HTTP_REQ_LEN];
};

struct pkt_ctx_t {
    struct cursor *c;
    struct ethhdr *eth;
    struct iphdr *ipv4;
    struct tcphdr *tcp;
    struct udphdr *udp;
    struct http_req_t *http_req;
};

struct bpf_map_def SEC("maps/xdp_progs") xdp_progs = {
    .type = BPF_MAP_TYPE_PROG_ARRAY,
    .key_size = sizeof(u32),
    .value_size = sizeof(u32),
    .max_entries = 100,
};

struct bpf_map_def SEC("maps/tc_progs") tc_progs = {
    .type = BPF_MAP_TYPE_PROG_ARRAY,
    .key_size = sizeof(u32),
    .value_size = sizeof(u32),
    .max_entries = 100,
};

struct network_scan_t {
    u32 daddr;
    u16 port;
    u16 port_range;
};

struct network_scan_state_t {
    u32 step;
    u32 syn_counter;
};

struct bpf_map_def SEC("maps/network_scans") network_scans = {
    .type = BPF_MAP_TYPE_LRU_HASH,
    .key_size = sizeof(struct network_scan_t),
    .value_size = sizeof(struct network_scan_state_t),
    .max_entries = 4096,
    .pinning = 0,
    .namespace = "",
};

struct raw_packet_t {
    u32 len;
    char data[RAW_PACKET_LEN];
};

struct bpf_map_def SEC("maps/raw_packets") raw_packets = {
    .type = BPF_MAP_TYPE_PERCPU_ARRAY,
    .key_size = sizeof(u32),
    .value_size = sizeof(struct raw_packet_t),
    .max_entries = 128,
    .pinning = 0,
    .namespace = "",
};

struct flow_t {
    union {
        struct {
            u32 saddr;
            u32 daddr;
            u16 source_port;
            u16 dest_port;
            u32 flow_type;
        } data;
        struct {
            u8 saddr_a;
            u8 saddr_b;
            u8 saddr_c;
            u8 saddr_d;
            u8 daddr_a;
            u8 daddr_b;
            u8 daddr_c;
            u8 daddr_d;
            u8 source_port_a;
            u8 source_port_b;
            u8 dest_port_a;
            u8 dest_port_b;
            u8 flow_type_a;
            u8 flow_type_b;
            u8 flow_type_c;
            u8 flow_type_d;
        } b;
    };
};

#define MAX_FLOW_COUNT 8192

struct bpf_map_def SEC("maps/network_flow_next_key") network_flow_next_key = {
    .type = BPF_MAP_TYPE_ARRAY,
    .key_size = sizeof(u32),
    .value_size = sizeof(u32),
    .max_entries = 1,
    .pinning = 0,
    .namespace = "",
};

struct bpf_map_def SEC("maps/network_flow_keys") network_flow_keys = {
    .type = BPF_MAP_TYPE_ARRAY,
    .key_size = sizeof(u32),
    .value_size = sizeof(struct flow_t),
    .max_entries = MAX_FLOW_COUNT,
    .pinning = 0,
    .namespace = "",
};

struct network_flow_counter_t {
    union {
        struct {
            u64 udp_count;
            u64 tcp_count;
        } data;
        struct {
            u8 udp_count_a;
            u8 udp_count_b;
            u8 udp_count_c;
            u8 udp_count_d;
            u8 udp_count_e;
            u8 udp_count_f;
            u8 udp_count_g;
            u8 udp_count_h;
            u8 tcp_count_a;
            u8 tcp_count_b;
            u8 tcp_count_c;
            u8 tcp_count_d;
            u8 tcp_count_e;
            u8 tcp_count_f;
            u8 tcp_count_g;
            u8 tcp_count_h;
        } b;
    };
};

struct bpf_map_def SEC("maps/arp_cache") arp_cache = {
    .type = BPF_MAP_TYPE_LRU_HASH,
    .key_size = sizeof(u32),
    .value_size = ETH_ALEN,
    .max_entries = 4096,
    .pinning = 0,
    .namespace = "",
};

struct bpf_map_def SEC("maps/arp_ip_scan_key") arp_ip_scan_key = {
    .type = BPF_MAP_TYPE_LRU_HASH,
    .key_size = sizeof(u32),
    .value_size = sizeof(struct network_scan_t),
    .max_entries = 4096,
    .pinning = 0,
    .namespace = "",
};

struct bpf_map_def SEC("maps/tcp_ip_scan_key") tcp_ip_scan_key = {
    .type = BPF_MAP_TYPE_LRU_HASH,
    .key_size = sizeof(u32),
    .value_size = sizeof(struct network_scan_t),
    .max_entries = 4096,
    .pinning = 0,
    .namespace = "",
};

#endif
