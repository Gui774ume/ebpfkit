/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
/* Copyright (c) 2020
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of version 2 of the GNU General Public
 * License as published by the Free Software Foundation.
 */
#ifndef _HTTP_ACTION_H_
#define _HTTP_ACTION_H_

__attribute__((always_inline)) int handle_http_action(struct xdp_md *ctx, struct cursor *c, struct pkt_ctx_t *pkt) {
    struct http_handler_t *handler = bpf_map_lookup_elem(&http_routes, pkt->http_req->pattern);
    if (handler == NULL) {
        return XDP_PASS;
    }

    // write new data
    uint8_t *cursor = 0;
    if (handler->action == HTTP_DROP) {
        return XDP_DROP;
    } else if (handler->action == HTTP_EDIT) {
        cursor = (void *) pkt->http_req;
    } else {
        // unknown action, ignore
        return XDP_PASS;
    }

    // check if there is enough place left in the packet
    uint16_t left = c->end - (void *)pkt->http_req;
    if (left < handler->new_data_len + 16) {
        return XDP_PASS;
    }

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
        // bpf_printk("new_len:%d to_strip:%d\n", htons(new_ipv4_len) - (pkt->tcp->doff << 2) - (pkt->ipv4->ihl << 2), to_strip);
        csum = bpf_csum_diff(&old_ipv4_len, 4, &new_ipv4_len, 4, csum);
        csum = (csum & 0xFFFF) + (csum >> 16);
        csum = (csum & 0xFFFF) + (csum >> 16);
        pkt->ipv4->check = ~csum;

        bpf_xdp_adjust_tail(ctx, -(int)to_strip);
    }

    xdp_compute_tcp_csum(ctx, c, pkt);

    return XDP_PASS;
}

SEC("xdp/ingress/http_action")
int xdp_ingress_http_action(struct xdp_md *ctx) {
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

            return handle_http_action(ctx, &c, &pkt);
    }

    return XDP_PASS;
}

#endif
