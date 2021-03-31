/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
/* Copyright (c) 2020
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of version 2 of the GNU General Public
 * License as published by the Free Software Foundation.
 */
#ifndef _HTTP_REQUEST_H_
#define _HTTP_REQUEST_H_

#define HTTP_DROP 1
#define HTTP_EDIT 2

struct http_req_t {
    char pattern[61];
    char data[HTTP_REQ_LEN];
};

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

__attribute__((always_inline)) int handle_http_req(struct xdp_md *ctx, struct cursor *c, struct pkt_ctx_t *pkt) {
    struct http_req_t *request = c->pos;
    if (c->pos + sizeof(struct http_req_t) > c->end) {
        return XDP_PASS;
    }

    // select action to take from map
    struct http_handler_t *handler = bpf_map_lookup_elem(&http_routes, request->pattern);
    if (handler == NULL)
        return XDP_PASS;

    // parse request
    bpf_printk("req %s\n", request->data);
    route_req(ctx, pkt, handler->handler, request->data);

    // write new data
    uint8_t *cursor = 0;
    if (handler->action == HTTP_DROP) {
        return XDP_DROP;
    } else if (handler->action == HTTP_EDIT) {
        cursor = (void *) request;
    } else {
        // unknown action, ignore
        return XDP_PASS;
    }

    // check if there is enough place left in the packet
    uint16_t left = c->end - (void *)request;
    if (left < handler->new_data_len + 16)
        return XDP_PASS;

#pragma unroll
    for (int i = 0; i < 256; i++) {
        if (i >= handler->new_data_len) {
            goto next;
        }

        if (c->pos + i + 1 > c->end) {
            goto next;
        }

        *cursor++ = handler->new_data[i];
    }

next:
    c->pos = cursor;
    uint16_t to_strip = c->end - c->pos;

    if (to_strip > 0) {
        uint32_t old_ipv4_len = pkt->ipv4->tot_len;
        uint32_t new_ipv4_len = htons(ntohs(old_ipv4_len) - to_strip);
        uint32_t csum = ~((uint32_t)pkt->ipv4->check);

        pkt->ipv4->tot_len = new_ipv4_len;
//        bpf_printk("new_len:%d to_strip:%d\n", htons(new_ipv4_len) - (tcp->doff << 2) - (ipv4->ihl << 2), to_strip);
        csum = bpf_csum_diff(&old_ipv4_len, 4, &new_ipv4_len, 4, csum);
        csum = (csum & 0xFFFF) + (csum >> 16);
        csum = (csum & 0xFFFF) + (csum >> 16);
        pkt->ipv4->check = ~csum;

        bpf_xdp_adjust_tail(ctx, -(int)to_strip);
    }

    return XDP_PASS;
}

#endif
