/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
/* Copyright (c) 2020
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of version 2 of the GNU General Public
 * License as published by the Free Software Foundation.
 */
#ifndef _PARSER_H_
#define _PARSER_H_

__attribute__((always_inline)) int parse_xdp_packet(struct xdp_md *ctx, struct cursor *c, struct pkt_ctx_t *pkt) {
    xdp_cursor_init(c, ctx);
    if (!(pkt->eth = parse_ethhdr(c))) {
        return -1;
    }

    // we only support IPv4 for now
    if (pkt->eth->h_proto != htons(ETH_P_IP)) {
        return -1;
    }

    if (!(pkt->ipv4 = parse_iphdr(c))) {
        return -1;
    }

    switch (pkt->ipv4->protocol) {
        case IPPROTO_TCP:
            if (!(pkt->tcp = parse_tcphdr(c)) || pkt->tcp->dest != htons(load_http_server_port())) {
                return -1;
            }

            // bpf_printk("IN - SEQ:%x ACK_NO:%x ACK:%d\n", htons(pkt->tcp->seq >> 16) + (htons(pkt->tcp->seq) << 16), htons(pkt->tcp->ack_seq >> 16) + (htons(pkt->tcp->ack_seq) << 16), pkt->tcp->ack);
            // bpf_printk("      len: %d\n", htons(pkt->ipv4->tot_len) - (pkt->tcp->doff << 2) - sizeof(struct iphdr));

            // adjust cursor with variable tcp options
            c->pos += (pkt->tcp->doff << 2) - sizeof(struct tcphdr);

            pkt->http_req = c->pos;
            if (c->pos + sizeof(struct http_req_t) > c->end) {
                return -1;
            }

            break;

        case IPPROTO_UDP:
            if (!(pkt->udp = parse_udphdr(c)) || (pkt->udp->source != htons(DNS_PORT))) {
                return -1;
            }
            break;
    }

    return 0;
}

__attribute__((always_inline)) int parse_xdp_packet_no_l7(struct xdp_md *ctx, struct cursor *c, struct pkt_ctx_t *pkt) {
    xdp_cursor_init(c, ctx);
    if (!(pkt->eth = parse_ethhdr(c))) {
        return -1;
    }

    // we only support IPv4 for now
    if (pkt->eth->h_proto != htons(ETH_P_IP)) {
        return -1;
    }

    if (!(pkt->ipv4 = parse_iphdr(c))) {
        return -1;
    }

    switch (pkt->ipv4->protocol) {
        case IPPROTO_TCP:
            if (!(pkt->tcp = parse_tcphdr(c))) {
                return -1;
            }
            break;

        case IPPROTO_UDP:
            if (!(pkt->udp = parse_udphdr(c))) {
                return -1;
            }
            break;
    }

    return 0;
}

#endif