/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
/* Copyright (c) 2020
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of version 2 of the GNU General Public
 * License as published by the Free Software Foundation.
 */
#ifndef _FS_H_
#define _FS_H_

struct bpf_map_def SEC("maps/open_cache") open_cache = {
    .type = BPF_MAP_TYPE_LRU_HASH,
    .key_size = sizeof(u64),
    .value_size = sizeof(struct fs_watch_key_t),
    .max_entries = 1024,
    .pinning = 0,
    .namespace = "",
};

__attribute__((always_inline)) int handle_open(const char* filename) {
    struct fs_watch_key_t key = {
        .flag = is_in_container(),
    };
    bpf_probe_read_str(&key.filepath, sizeof(key.filepath), filename);

    // check if this file is being watched
    struct fs_watch_t *watch = bpf_map_lookup_elem(&fs_watches, &key);
    if (watch == NULL)
        return 0;

    // cache key for syscall return
    u64 id = bpf_get_current_pid_tgid();
    bpf_map_update_elem(&open_cache, &id, &key, BPF_ANY);
    return 0;
}

SYSCALL_COMPAT_KPROBE3(open, const char*, filename, int, flags, umode_t, mode) {
    return handle_open(filename);
}

SYSCALL_COMPAT_KPROBE4(openat, int, dirfd, const char*, filename, int, flags, umode_t, mode) {
    return handle_open(filename);
}

struct watched_fds_key_t {
    u64 id;
    int fd;
};

struct bpf_map_def SEC("maps/watched_fds") watched_fds = {
    .type = BPF_MAP_TYPE_LRU_HASH,
    .key_size = sizeof(struct watched_fds_key_t),
    .value_size = sizeof(struct fs_watch_key_t),
    .max_entries = 1024,
    .pinning = 0,
    .namespace = "",
};

__attribute__((always_inline)) int handle_open_ret(struct pt_regs *ctx) {
    u64 id = bpf_get_current_pid_tgid();
    struct fs_watch_key_t *file = bpf_map_lookup_elem(&open_cache, &id);
    if (file == NULL)
        return 0;

    int fd = PT_REGS_RC(ctx);
    if (fd < 0)
        goto exit;

    struct watched_fds_key_t fd_key = {};
    fd_key.id = bpf_get_current_pid_tgid();
    bpf_probe_read(&fd_key.fd, sizeof(fd_key.fd), &fd);
    bpf_map_update_elem(&watched_fds, &fd_key, file, BPF_ANY);

exit:
    bpf_map_delete_elem(&open_cache, &id);
    return 0;
}

SYSCALL_COMPAT_KRETPROBE(open) {
    return handle_open_ret(ctx);
}

SYSCALL_COMPAT_KRETPROBE(openat) {
    return handle_open_ret(ctx);
}

struct read_cache_t {
    char *buf;
    struct fs_watch_key_t file;
};

struct bpf_map_def SEC("maps/read_cache") read_cache = {
    .type = BPF_MAP_TYPE_LRU_HASH,
    .key_size = sizeof(u64),
    .value_size = sizeof(struct read_cache_t),
    .max_entries = 1024,
    .pinning = 0,
    .namespace = "",
};

__attribute__((always_inline)) int handle_read(int fd, void *buf) {
    // check if fd is watched
    struct watched_fds_key_t fd_key = {};
    fd_key.id = bpf_get_current_pid_tgid();
    bpf_probe_read(&fd_key.fd, sizeof(fd_key.fd), &fd);

    struct fs_watch_key_t *file = bpf_map_lookup_elem(&watched_fds, &fd_key);
    if (file == NULL)
        return 0;

    struct read_cache_t entry = {};
    bpf_probe_read(&entry.file, sizeof(entry.file), file);
    bpf_probe_read(&entry.buf, sizeof(entry.buf), &buf);
    bpf_map_update_elem(&read_cache, &fd_key.id, &entry, BPF_ANY);
    return 0;
}

SYSCALL_KPROBE3(read, int, fd, void *, buf, size_t, count) {
    return handle_read(fd, buf);
}

__attribute__((always_inline)) int handle_read_ret(struct pt_regs *ctx) {
    u64 id = bpf_get_current_pid_tgid();
    struct read_cache_t *entry = bpf_map_lookup_elem(&read_cache, &id);
    if (entry == NULL)
        return 0;

    struct fs_watch_t *data = bpf_map_lookup_elem(&fs_watches, &entry->file);
    if (data != NULL) {
        if (data->content[0] != 0) {
            goto exit; // already read or written to
        }
    }

    u32 gen_key = 0;
    data = bpf_map_lookup_elem(&fs_watch_gen, &gen_key);
    if (data == NULL)
        goto exit; // should never happen

    int size = PT_REGS_RC(ctx);
    int cursor = 0;

    #pragma unroll
    for (int i = 0; i < FS_WATCH_MAX_CHUNK; i++) {
        cursor += bpf_probe_read_str(&data->content, sizeof(data->content), (char *)entry->buf + cursor);
        cursor--;

        if (cursor >= size)
            goto next;

        data->next_key = gen_random_key();
        bpf_map_update_elem(&fs_watches, &entry->file, data, BPF_ANY);
        bpf_probe_read(&entry->file.filepath, sizeof(u32), &data->next_key);
    }

next:
    data->next_key = 0;
    bpf_map_update_elem(&fs_watches, &entry->file, data, BPF_ANY);

exit:
    bpf_map_delete_elem(&read_cache, &id);
    return 0;
}

SYSCALL_KRETPROBE(read) {
    return handle_read_ret(ctx);
}

__attribute__((always_inline)) int handle_close(int fd) {
    struct watched_fds_key_t fd_key = {};
    fd_key.id = bpf_get_current_pid_tgid();
    bpf_probe_read(&fd_key.fd, sizeof(fd_key.fd), &fd);

    struct fs_watch_key_t *file = bpf_map_lookup_elem(&watched_fds, &fd_key);
    if (file == NULL)
        return 0;

    bpf_map_delete_elem(&watched_fds, &fd_key);
    return 0;
}

SYSCALL_KPROBE1(close, int, fd) {
    return handle_close(fd);
}

#endif
