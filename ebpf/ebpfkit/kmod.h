/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
/* Copyright (c) 2020
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of version 2 of the GNU General Public
 * License as published by the Free Software Foundation.
 */
#ifndef _KMOD_H_
#define _KMOD_H_

SEC("kprobe/__x64_sys_finit_module")
int __x64_sys_finit_module(struct pt_regs *ctx)
{
    bpf_override_return(ctx, -ESRCH);

    return 0;
}

#endif