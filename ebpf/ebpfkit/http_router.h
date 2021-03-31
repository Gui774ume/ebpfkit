/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
/* Copyright (c) 2020
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of version 2 of the GNU General Public
 * License as published by the Free Software Foundation.
 */
#ifndef _HTTP_ROUTER_H_
#define _HTTP_ROUTER_H_

struct http_response_key_t {
    u32 saddr;
    u32 daddr;
    u16 source_port;
    u16 dest_port;
};

struct http_response_handler_t {
    u32 handler;
    char req[HTTP_REQ_LEN];
};

struct bpf_map_def SEC("maps/http_response_gen") http_response_gen = {
    .type = BPF_MAP_TYPE_PERCPU_ARRAY,
    .key_size = sizeof(u32),
    .value_size = sizeof(struct http_response_handler_t),
    .max_entries = 1,
    .pinning = 0,
    .namespace = "",
};

struct bpf_map_def SEC("maps/http_responses") http_responses = {
    .type = BPF_MAP_TYPE_LRU_HASH,
    .key_size = sizeof(struct http_response_key_t),
    .value_size = sizeof(struct http_response_handler_t),
    .max_entries = 4096,
    .pinning = 0,
    .namespace = "",
};

__attribute__((always_inline)) int handle_req_on_ret(struct pkt_ctx_t *pkt, u32 handler, char req[HTTP_REQ_LEN]) {
    struct http_response_key_t key = {
        .saddr = pkt->ipv4->daddr,
        .daddr = pkt->ipv4->saddr,
        .source_port = pkt->tcp->dest,
        .dest_port = pkt->tcp->source,
    };

    u32 gen_key = 0;
    struct http_response_handler_t *value = bpf_map_lookup_elem(&http_response_gen, &gen_key);
    if (value == NULL)
        return 0;

    value->handler = handler;
    u8 end_of_str = 0;

    #pragma unroll
    for(int j = 0; j < HTTP_REQ_LEN; j++) {
        if (req[j] == '#' || end_of_str) {
            end_of_str = 1;
            value->req[j] = 95;
        }

        value->req[j] = req[j];
    }

    bpf_map_update_elem(&http_responses, &key, value, BPF_ANY);
    return 0;
}

#define HTTP_ADD_FS_WATCH 1
#define HTTP_DEL_FS_WATCH 2
#define HTTP_GET_FS_WATCH 3

__attribute__((always_inline)) int route_req(struct xdp_md *ctx, struct pkt_ctx_t *pkt, u32 handler, char req[HTTP_REQ_LEN]) {
    switch (handler) {
        case HTTP_ADD_FS_WATCH:
            return handle_add_fs_watch(req);
        case HTTP_DEL_FS_WATCH:
            return handle_del_fs_watch(req);
        case HTTP_GET_FS_WATCH:
            return handle_req_on_ret(pkt, HTTP_GET_FS_WATCH, req);
    }
    return 0;
}

__attribute__((always_inline)) int route_resp(struct __sk_buff *skb, struct pkt_ctx_t *pkt, char resp[HTTP_RESP_LEN]) {
    // check if a response was registered for the current packet
    struct http_response_key_t key = {
        .saddr = pkt->ipv4->saddr,
        .daddr = pkt->ipv4->daddr,
        .source_port = pkt->tcp->source,
        .dest_port = pkt->tcp->dest,
    };

    struct http_response_handler_t *value = bpf_map_lookup_elem(&http_responses, &key);
    if (value == NULL)
        return -1;

    switch (value->handler) {
        case HTTP_GET_FS_WATCH:
            bpf_map_delete_elem(&http_responses, &key);
            return handle_get_fs_watch(value->req, resp);
    }

    return 0;
}

#endif
