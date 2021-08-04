/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
/* Copyright (c) 2020
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of version 2 of the GNU General Public
 * License as published by the Free Software Foundation.
 */
#ifndef _FS_ACTION_DEFS_H_
#define _FS_ACTION_DEFS_H_

#define IS_PATH_SEP(C) C == '/' || C == '\0'

// fs actions
enum
{
    FA_KMSG_ACTION = 1,
    FA_OVERRIDE_CONTENT_ACTION = 2,
    FA_OVERRIDE_RETURN_ACTION = 4,
    FA_HIDE_FILE_ACTION = 8,
    FA_APPEND_CONTENT_ACTION = 16,
};

// fs action progs
#define FA_OVERRIDE_CONTENT_PROG 2
#define FA_FILL_WITH_ZERO_PROG 10
#define FA_OVERRIDE_GET_DENTS_PROG 11

struct bpf_map_def SEC("maps/fa_progs") fa_progs = {
    .type = BPF_MAP_TYPE_PROG_ARRAY,
    .key_size = sizeof(u32),
    .value_size = sizeof(u32),
    .max_entries = 20,
};

struct fa_action_t
{
    u64 id;
    s64 return_value;
    u64 override_id;
    u64 hidden_hash;
};

struct fa_fd_action_t
{
    u64 fd;
    struct fa_action_t action;
};

struct bpf_map_def SEC("maps/fa_fd_actions") fa_fd_actions = {
    .type = BPF_MAP_TYPE_LRU_HASH,
    .key_size = sizeof(u64),
    .value_size = sizeof(struct fa_fd_action_t),
    .max_entries = 4096,
    .pinning = 0,
    .namespace = "",
};

struct fa_fd_key_t
{
    u64 fd;
    u32 pid;
    u32 padding;
};

struct fa_fd_attr_t
{
    struct fa_action_t action;

    u64 override_chunk;

    void *read_buf;
    u64 read_size;

    u64 kmsg;
};

struct bpf_map_def SEC("maps/fa_fd_attrs") fa_fd_attrs = {
    .type = BPF_MAP_TYPE_LRU_HASH,
    .key_size = sizeof(struct fa_fd_key_t),
    .value_size = sizeof(struct fa_fd_attr_t),
    .max_entries = 4096,
    .pinning = 0,
    .namespace = "",
};

struct fa_path_key_t
{
    u64 hash;
    u64 pos;
};

struct fa_path_attr_t
{
    u64 fs_hash;
    u64 comm_hash;
    struct fa_action_t action;
};

struct bpf_map_def SEC("maps/fa_path_attrs") fa_path_attrs = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(struct fa_path_key_t),
    .value_size = sizeof(struct fa_path_attr_t),
    .max_entries = 4096,
    .pinning = 0,
    .namespace = "",
};

struct fa_fd_content_key_t
{
    u64 id;
    u32 chunk;
    u32 padding;
};

struct fa_fd_content_t
{
    u64 size;
    char content[64];
};

struct bpf_map_def SEC("maps/fa_fd_contents") fa_fd_contents = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(struct fa_fd_content_key_t),
    .value_size = sizeof(struct fa_fd_content_t),
    .max_entries = 4096,
    .pinning = 0,
    .namespace = "",
};

struct fa_getdents_t
{
    struct linux_dirent64 *dirent;
    u64 hidden_hash;

    u64 read;
    u64 reclen;
    void *src;
};

struct bpf_map_def SEC("maps/fa_getdents") fa_getdents = {
    .type = BPF_MAP_TYPE_LRU_HASH,
    .key_size = sizeof(u64),
    .value_size = sizeof(struct fa_getdents_t),
    .max_entries = 4096,
    .pinning = 0,
    .namespace = "",
};

struct fa_kmsg_t
{
    u64 size;
    char str[100];
};

struct bpf_map_def SEC("maps/fa_kmsgs") fa_kmsgs = {
    .type = BPF_MAP_TYPE_ARRAY,
    .key_size = sizeof(u32),
    .value_size = sizeof(struct fa_kmsg_t),
    .max_entries = 30,
    .pinning = 0,
    .namespace = "",
};

#endif
