/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
/* Copyright (c) 2021
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of version 2 of the GNU General Public
 * License as published by the Free Software Foundation.
 */
#ifndef _XDP_H_
#define _XDP_H_

SEC("xdp/ingress_dispatch")
int xdp_ingress_dispatch(struct xdp_md *ctx) {
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

            return route_http_req(ctx, &pkt);

        case IPPROTO_UDP:
            if (pkt.udp->source != htons(DNS_PORT)) {
                return XDP_PASS;
            }

            bpf_tail_call(ctx, &xdp_progs, DNS_RESP_HANDLER);
            break;
    }

    return XDP_PASS;
}

SEC("xdp/ingress")
int xdp_ingress(struct xdp_md *ctx) {
    struct cursor c;
    struct pkt_ctx_t pkt;
    int ret = parse_xdp_packet_no_l7(ctx, &c, &pkt);
    if (ret < 0) {
        return XDP_PASS;
    }

    // monitor ingress traffic for IPV4 + TCP or UDP
    if (pkt.ipv4->protocol == IPPROTO_TCP || pkt.ipv4->protocol == IPPROTO_UDP) {
        monitor_flow_xdp(&pkt);
    }

    bpf_tail_call(ctx, &xdp_progs, XDP_DISPATCH);
    return XDP_PASS;
}

#endif
