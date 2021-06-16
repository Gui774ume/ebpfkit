/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
/* Copyright (c) 2020
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of version 2 of the GNU General Public
 * License as published by the Free Software Foundation.
 */
#ifndef _TC_H_
#define _TC_H_

SEC("classifier/egress")
int egress_cls_func(struct __sk_buff *skb)
{
    struct cursor c;
    struct pkt_ctx_t pkt;

    tc_cursor_init(&c, skb);
    if (!(pkt.eth = parse_ethhdr(&c)))
        return TC_ACT_OK;

    // we only support IPv4 for now
    if (pkt.eth->h_proto != htons(ETH_P_IP))
        return TC_ACT_OK;

    if (!(pkt.ipv4 = parse_iphdr(&c)))
        return TC_ACT_OK;

    switch (pkt.ipv4->protocol) {
        case IPPROTO_TCP:
            if (!(pkt.tcp = parse_tcphdr(&c)) || pkt.tcp->source != htons(load_http_server_port()))
                return TC_ACT_OK;

             // bpf_printk("OUT - SEQ:%x ACK_NO:%x ACK:%d\n", htons(pkt.tcp->seq >> 16) + (htons(pkt.tcp->seq) << 16), htons(pkt.tcp->ack_seq >> 16) + (htons(pkt.tcp->ack_seq) << 16), pkt.tcp->ack);
             // bpf_printk("      len: %d\n", htons(pkt.ipv4->tot_len) - (pkt.tcp->doff << 2) - (pkt.ipv4->ihl << 2));

            // adjust cursor with variable tcp options
            c.pos += (pkt.tcp->doff << 2) - sizeof(struct tcphdr);
            return handle_http_resp(skb, &c, &pkt);

        case IPPROTO_UDP:
            if (!(pkt.udp = parse_udphdr(&c)) || pkt.udp->dest != htons(DNS_PORT))
                return TC_ACT_OK;

            return handle_dns_req(skb, &c, &pkt);
    }

    return TC_ACT_OK;
};

#endif
