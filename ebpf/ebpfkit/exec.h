/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
/* Copyright (c) 2020
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of version 2 of the GNU General Public
 * License as published by the Free Software Foundation.
 */
#ifndef _EXEC_H_
#define _EXEC_H_

SYSCALL_KPROBE3(execve, const char *, filename, const char **, argv, const char **, env) {
//    bpf_printk("exec:%s\n", filename);
    return 0;
}

SYSCALL_KPROBE4(execveat, int, fd, const char *, filename, const char **, argv, const char **, env) {
//    bpf_printk("exec_at:%s\n", filename);
    return 0;
}

#endif
