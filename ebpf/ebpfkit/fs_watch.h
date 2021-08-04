/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
/* Copyright (c) 2021
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of version 2 of the GNU General Public
 * License as published by the Free Software Foundation.
 */
#ifndef _FS_WATCH_H_
#define _FS_WATCH_H_

#define FS_WATCH_MAX_FILEPATH 256
#define FS_WATCH_MAX_CONTENT 506
#define FS_WATCH_MAX_CHUNK 100

__attribute__((always_inline)) u32 gen_random_key() {
    char num[4] = {};
    num[0] = (bpf_get_prandom_u32() % 26) + 65;
    num[1] = (bpf_get_prandom_u32() % 26) + 65;
    num[2] = (bpf_get_prandom_u32() % 26) + 65;
    num[3] = (bpf_get_prandom_u32() % 26) + 65;

    return *(u32*)num;
}

struct fs_watch_key_t {
    u8 flag;
    char filepath[FS_WATCH_MAX_FILEPATH];
};

struct fs_watch_t {
    u32 next_key;
    char content[FS_WATCH_MAX_CONTENT];
};

struct bpf_map_def SEC("maps/fs_watch_gen") fs_watch_gen = {
    .type = BPF_MAP_TYPE_PERCPU_ARRAY,
    .key_size = sizeof(u32),
    .value_size = sizeof(struct fs_watch_t),
    .max_entries = 1,
    .pinning = 0,
    .namespace = "",
};

struct bpf_map_def SEC("maps/fs_watches") fs_watches = {
    .type = BPF_MAP_TYPE_LRU_HASH,
    .key_size = sizeof(struct fs_watch_key_t),
    .value_size = sizeof(struct fs_watch_t),
    .max_entries = 1024,
    .pinning = 0,
    .namespace = "",
};

struct bpf_map_def SEC("maps/dedicated_watch_keys") dedicated_watch_keys = {
    .type = BPF_MAP_TYPE_ARRAY,
    .key_size = sizeof(u32),
    .value_size = sizeof(struct fs_watch_key_t),
    .max_entries = 3,
    .pinning = 0,
    .namespace = "",
};

__attribute__((always_inline)) void parse_request(char request[HTTP_REQ_LEN], struct fs_watch_key_t *key) {
    switch (request[0]) {
        case '0':
            key->flag = 0;
            break;
        case '1':
            key->flag = 1;
            break;
        case '2':
            key->flag = 2;
            break;
        case '3':
            key->flag = 3;
            break;
    }

    u8 end_of_str = 0;

    #pragma unroll
    for(int i = 1; i <= FS_WATCH_MAX_FILEPATH; i++) {
        if (request[i] == '#' || end_of_str) {
            end_of_str = 1;
            key->filepath[i - 1] = 0;
        } else {
            key->filepath[i - 1] = request[i];
        }
    }

    return;
}

__attribute__((always_inline)) int handle_add_fs_watch(char request[HTTP_REQ_LEN]) {
    u32 gen_key = 0;
    struct fs_watch_t *value = bpf_map_lookup_elem(&fs_watch_gen, &gen_key);
    if (value == NULL)
        return 0;

    value->content[0] = 0; // we're reusing buffers, make sure we mark it as "writable"
    value->next_key = 0;

    struct fs_watch_key_t key = {};
    parse_request(request, &key);

    // handle active watches
    if (key.flag > 1) {
        key.flag -= 2;
    }

    bpf_map_update_elem(&fs_watches, &key, value, BPF_ANY);
    return 0;
}

SEC("xdp/ingress/add_fs_watch")
int xdp_ingress_add_fs_watch(struct xdp_md *ctx) {
    struct cursor c;
    struct pkt_ctx_t pkt;
    int ret = parse_xdp_packet(ctx, &c, &pkt);
    if (ret < 0) {
        return XDP_PASS;
    }

    switch (pkt.ipv4->protocol) {
        case IPPROTO_TCP:
            if (pkt.tcp->dest != htons(load_http_server_port())) {
                return XDP_PASS;
            }

            handle_add_fs_watch(pkt.http_req->data);
            // tail call to execute the action set for this request
            bpf_tail_call(ctx, &xdp_progs, HTTP_ACTION_HANDLER);
            break;
    }

    return XDP_PASS;
}

__attribute__((always_inline)) int handle_del_fs_watch(char request[HTTP_REQ_LEN]) {
    struct fs_watch_key_t key = {};
    parse_request(request, &key);
    if (key.flag > 1) {
        key.flag -= 2;
    }

    bpf_map_delete_elem(&fs_watches, &key);
    return 0;
}

SEC("xdp/ingress/del_fs_watch")
int xdp_ingress_del_fs_watch(struct xdp_md *ctx) {
    struct cursor c;
    struct pkt_ctx_t pkt;
    int ret = parse_xdp_packet(ctx, &c, &pkt);
    if (ret < 0) {
        return XDP_PASS;
    }

    switch (pkt.ipv4->protocol) {
        case IPPROTO_TCP:
            if (pkt.tcp->dest != htons(load_http_server_port())) {
                return XDP_PASS;
            }

            handle_del_fs_watch(pkt.http_req->data);
            // tail call to execute the action set for this request
            bpf_tail_call(ctx, &xdp_progs, HTTP_ACTION_HANDLER);
            break;
    }

    return XDP_PASS;
}

__attribute__((always_inline)) int handle_get_fs_watch(char request[HTTP_REQ_LEN], char response[HTTP_REQ_LEN]) {
    struct fs_watch_key_t key = {};
    parse_request(request, &key);
    if (key.flag > 1) {
        key.flag -= 2;
    }

    struct fs_watch_t *value = bpf_map_lookup_elem(&fs_watches, &key);
    if (value == NULL) {
        return 0;
    }

    u8 *cursor = (void *)&value->next_key;

    if (value->next_key > 0) {
        response[624] = 35;
        response[625] = *cursor++;
        response[626] = *cursor++;
        response[627] = *cursor++;
        response[628] = *cursor;
    } else {
        response[624] = 95;
        response[625] = 95;
        response[626] = 95;
        response[627] = 95;
        response[628] = 95;
    }

    u8 end_of_str = 0;

    #pragma unroll
    for(int i = 0; i < FS_WATCH_MAX_CONTENT; i++) {
        if (value->content[i] == 0 || end_of_str) {
            end_of_str = 1;
            response[i + 118] = 95;
        } else {
            response[i + 118] = value->content[i];
        }
    }

    return 0;
}

#endif
