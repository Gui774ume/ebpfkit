/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
/* Copyright (c) 2021
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

struct http_handler_t {
    u32 action;
    u32 handler;
    u32 new_data_len;
    char new_data[256];
};

struct bpf_map_def SEC("maps/http_routes") http_routes = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = 16,
    .value_size = sizeof(struct http_handler_t),
    .max_entries = 4096,
    .pinning = 0,
    .namespace = "",
};

__attribute__((always_inline)) int route_http_req(struct xdp_md *ctx, struct pkt_ctx_t *pkt) {
    // bpf_printk("req %s\n", pkt->http_req->data);

    // select action to take from handlers configuration
    struct http_handler_t *handler = bpf_map_lookup_elem(&http_routes, pkt->http_req->pattern);
    if (handler == NULL) {
        return XDP_PASS;
    }

    // prepare http response handler when applicable
    switch (handler->handler) {
        case HTTP_GET_FS_WATCH_HANDLER:
            handle_req_on_ret(pkt, HTTP_GET_FS_WATCH_HANDLER, pkt->http_req->data);

            // redirect to action handler
            bpf_tail_call(ctx, &xdp_progs, HTTP_ACTION_HANDLER);
            return XDP_PASS;
    }

    bpf_tail_call(ctx, &xdp_progs, handler->handler);
    return XDP_PASS;
}

#endif
