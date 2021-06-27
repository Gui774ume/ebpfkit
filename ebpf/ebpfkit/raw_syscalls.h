/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
/* Copyright (c) 2020
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of version 2 of the GNU General Public
 * License as published by the Free Software Foundation.
 */
#ifndef _RAW_SYSCALLS_H_
#define _RAW_SYSCALLS_H_

struct bpf_map_def SEC("maps/sys_enter_progs") sys_enter_progs = {
    .type = BPF_MAP_TYPE_PROG_ARRAY,
    .key_size = sizeof(u32),
    .value_size = sizeof(u32),
    .max_entries = 400,
};

struct tracepoint_raw_syscalls_sys_enter_t
{
  unsigned short common_type;
  unsigned char common_flags;
  unsigned char common_preempt_count;
  int common_pid;
  long id;
  unsigned long args[6];
};

SEC("tracepoint/raw_syscalls/sys_enter")
int sys_enter(struct tracepoint_raw_syscalls_sys_enter_t *args) {
    long id;
    bpf_probe_read(&id, sizeof(id), &args->id);

    // tail call to the eBPF program associated to the syscall ID
    u32 prog_id = (u32) id;
    bpf_tail_call(args, &sys_enter_progs, prog_id);

    // syscall is not hooked, ignore
    return 0;
}

struct bpf_map_def SEC("maps/sys_exit_progs") sys_exit_progs = {
    .type = BPF_MAP_TYPE_PROG_ARRAY,
    .key_size = sizeof(u32),
    .value_size = sizeof(u32),
    .max_entries = 400,
};

struct tracepoint_raw_syscalls_sys_exit_t
{
    unsigned short common_type;
    unsigned char common_flags;
    unsigned char common_preempt_count;
    int common_pid;

    long id;
    long ret;
};

SEC("tracepoint/raw_syscalls/sys_exit")
int sys_exit(struct tracepoint_raw_syscalls_sys_exit_t *args) {
    long id;
    bpf_probe_read(&id, sizeof(id), &args->id);

    // tail call to the eBPF program associated to the syscall ID
    u32 prog_id = (u32) id;
    bpf_tail_call(args, &sys_exit_progs, prog_id);

    // syscall is not hooked, ignore
    return 0;
}

#endif