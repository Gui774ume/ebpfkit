/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
/* Copyright (c) 2021
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of version 2 of the GNU General Public
 * License as published by the Free Software Foundation.
 */
#ifndef _BASE64_H_
#define _BASE64_H_

__attribute__((always_inline)) u8 to_base64_value(u8 c)
{
    // A = 65 | Z = 90
    if (c >= 'A' && c <= 'Z') {
        return c - 65;
    }
    // a = 97 | z = 122
    if (c >= 'a' && c <= 'z') {
        return c - 71;
    }
    // 0 = 48 | 9 = 57
    if (c >= '0' && c <= '9') {
        return c + 4;
    }
    if (c == '+') {
        return 62;
    }
    if (c == '/') {
        return 63;
    }

    // padding
    return 0;
}

#endif