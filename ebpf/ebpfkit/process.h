/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
/* Copyright (c) 2021
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of version 2 of the GNU General Public
 * License as published by the Free Software Foundation.
 */
#ifndef _PROCESS_H_
#define _PROCESS_H_

__attribute__((always_inline)) u64 get_comm_hash()
{
    char comm[32];
    bpf_get_current_comm(&comm, sizeof(comm));

    u64 hash = FNV_BASIS;
    update_hash_str(&hash, comm);

    return hash;
}

#endif