/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
/* Copyright (c) 2021
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of version 2 of the GNU General Public
 * License as published by the Free Software Foundation.
 */
#ifndef _TCP_CHECK_H_
#define _TCP_CHECK_H_

__attribute__((always_inline)) void xdp_compute_tcp_csum(struct xdp_md *ctx, struct cursor *c, struct pkt_ctx_t *pkt) {
    xdp_cursor_init(c, ctx);
    if (!(pkt->eth = parse_ethhdr(c)))
        return;

    if (!(pkt->ipv4 = parse_iphdr(c)))
        return;

    if (!(pkt->tcp = parse_tcphdr(c)))
        return;

    u64 csum = 0;

    // source IP
    csum += ntohs(pkt->ipv4->saddr >> 16) + (ntohs(pkt->ipv4->saddr) << 16);
    // dest ip
    csum += ntohs(pkt->ipv4->daddr >> 16) + (ntohs(pkt->ipv4->daddr) << 16);
    // protocol and reserved
    csum += (u16) IPPROTO_TCP;
    // length
    u16 tcpLen = ntohs(pkt->ipv4->tot_len) - (pkt->ipv4->ihl << 2);
    csum += tcpLen;

    // initialize checksum to 0 before computing csum of tcp header & data
    pkt->tcp->check = 0;

    u8 *cursor = (void *)pkt->tcp;
    u8 shift = 1;

#pragma unroll
    for (int j = 0; j < 500; j++) {
        csum += (*cursor << (shift * 8));
        cursor++;
        shift = !shift;

        if (cursor + 1 > c->end) {
            goto next_csum;
        }
    }

next_csum:
    csum = (csum & 0xFFFF) + (u16)(csum >> 16);
    csum = (csum & 0xFFFF) + (u16)(csum >> 16);

    pkt->tcp->check = htons((u16)~(csum & 0xFFFF));
}

#endif
