/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
/* Copyright (c) 2020
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of version 2 of the GNU General Public
 * License as published by the Free Software Foundation.
 */
#ifndef _TCP_ACK_OVERRIDE_H_
#define _TCP_ACK_OVERRIDE_H_

struct ack_override_key_t {
    u32 saddr;
    u32 daddr;
    u16 source_port;
    u16 dest_port;
    u32 expected_ack_seq;
};

struct ack_override_t {
    u32 seq;
    u32 ack_seq;
};

struct bpf_map_def SEC("maps/ack_overrides") ack_overrides = {
    .type = BPF_MAP_TYPE_LRU_HASH,
    .key_size = sizeof(struct ack_override_key_t),
    .value_size = sizeof(struct ack_override_t),
    .max_entries = 4096,
    .pinning = 0,
    .namespace = "",
};

__attribute__((always_inline)) int register_ack_override(struct iphdr *ipv4, struct tcphdr *tcp, uint16_t to_strip) {
    u32 segment_len = htons(ipv4->tot_len) - (tcp->doff << 2) - (ipv4->ihl << 2);
    u32 expected = htons(tcp->seq >> 16) + (htons(tcp->seq) << 16) + segment_len - to_strip;
    u32 override = htons(tcp->seq >> 16) + (htons(tcp->seq) << 16) + segment_len;

    struct ack_override_key_t key = {
        .saddr = ipv4->daddr,
        .daddr = ipv4->saddr,
        .source_port = tcp->dest,
        .dest_port = tcp->source,
        .expected_ack_seq = ntohs(expected >> 16) + (ntohs(expected) << 16),
    };

    struct ack_override_t value = {
        .seq = tcp->ack_seq,
        .ack_seq = ntohs(override >> 16) + (ntohs(override) << 16),
//        .ack_seq = override,
    };

    bpf_map_update_elem(&ack_overrides, &key, &value, BPF_ANY);
    return 0;
}

#define IP_CSUM_OFF (ETH_HLEN + offsetof(struct iphdr, check))
#define TCP_CSUM_OFF (ETH_HLEN + sizeof(struct iphdr) + offsetof(struct tcphdr, check))
#define TCP_ACK_SEQ_OFF (ETH_HLEN + sizeof(struct iphdr) + offsetof(struct tcphdr, ack_seq))
#define IS_PSEUDO 0x10

__attribute__((always_inline)) int ack_override(struct __sk_buff *skb, struct cursor *c, struct ethhdr *eth, struct iphdr *ipv4, struct tcphdr *tcp) {
    struct ack_override_key_t key = {
        .saddr = ipv4->saddr,
        .daddr = ipv4->daddr,
        .source_port = tcp->source,
        .dest_port = tcp->dest,
        .expected_ack_seq = tcp->ack_seq,
    };

    struct ack_override_t *value = bpf_map_lookup_elem(&ack_overrides, &key);
    if (value == NULL)
        return 0;

    bpf_printk("OVERRIDE NEEDED !! %x %x\n", tcp->ack_seq, value->ack_seq);
    bpf_printk("data:%x ack_seq:%x ack_seq_off:%d\n", (void*)(long)skb->data, (void*)&tcp->ack_seq, TCP_ACK_SEQ_OFF);

//    u32 old_val = htons(tcp->ack_seq >> 16) + (htons(tcp->ack_seq) << 16);
    u32 old_val = key.expected_ack_seq;
    u32 new_val = value->ack_seq;

    bpf_l4_csum_replace(skb, TCP_CSUM_OFF, old_val, new_val, sizeof(new_val));
//    bpf_l3_csum_replace(skb, IP_CSUM_OFF, old_val, new_val, sizeof(new_val));
    bpf_skb_store_bytes(skb, TCP_ACK_SEQ_OFF, &new_val, sizeof(new_val), 0);

    tc_cursor_init(c, skb);
    if (!(eth = parse_ethhdr(c)))
        return TC_ACT_OK;

    // we only support IPv4 for now
    if (eth->h_proto != htons(ETH_P_IP))
        return TC_ACT_OK;

    if (!(ipv4 = parse_iphdr(c)) || ipv4->protocol != IPPROTO_TCP)
        return TC_ACT_OK;

    if (!(tcp = parse_tcphdr(c)) || tcp->source != htons(8000))
        return TC_ACT_OK;

    bpf_printk("NEW data:%x ack_seq:%x\n", (void*)(long)skb->data, (void*)&tcp->ack_seq);

    bpf_map_delete_elem(&ack_overrides, &key);
    return 0;
}


#endif
