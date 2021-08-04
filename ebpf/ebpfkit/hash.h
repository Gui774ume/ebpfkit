/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
/* Copyright (c) 2021
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of version 2 of the GNU General Public
 * License as published by the Free Software Foundation.
 */
#ifndef _HASH_H_
#define _HASH_H_

// Fowler/Noll/Vo hash
#define FNV_BASIS ((__u64)14695981039346656037U)
#define FNV_PRIME ((__u64)1099511628211U)

#define __update_hash(key, data) \
    *key ^= (__u64)(data);       \
    *key *= FNV_PRIME;

__attribute__((always_inline)) void update_hash_byte(__u64 *key, __u8 byte)
{
    __update_hash(key, byte);
}

__attribute__((always_inline)) void update_hash_str(__u64 *hash, const char *str)
{
#pragma unroll
    for (int i = 0; i != FS_MAX_SEGMENT_LENGTH; i++)
    {
        if (str[i] == '\0')
            break;
        update_hash_byte(hash, str[i]);
    }
}

#endif