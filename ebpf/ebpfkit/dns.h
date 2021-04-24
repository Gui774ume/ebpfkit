/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
/* Copyright (c) 2020
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of version 2 of the GNU General Public
 * License as published by the Free Software Foundation.
 */
#ifndef _DNS_H_
#define _DNS_H_

struct dnshdr {
    uint16_t id;
    union {
        struct {
            uint8_t  rd     : 1;
            uint8_t  tc     : 1;
            uint8_t  aa     : 1;
            uint8_t  opcode : 4;
            uint8_t  qr     : 1;

            uint8_t  rcode  : 4;
            uint8_t  cd     : 1;
            uint8_t  ad     : 1;
            uint8_t  z      : 1;
            uint8_t  ra     : 1;
        }        as_bits_and_pieces;
        uint16_t as_value;
    } flags;
    uint16_t qdcount;
    uint16_t ancount;
    uint16_t nscount;
    uint16_t arcount;
};

PARSE_FUNC(dnshdr)

struct dns_name_t {
    char name[DNS_MAX_LENGTH];
};

struct bpf_map_def SEC("maps/dns_name_gen") dns_name_gen = {
    .type = BPF_MAP_TYPE_PERCPU_ARRAY,
    .key_size = sizeof(u32),
    .value_size = sizeof(struct dns_name_t),
    .max_entries = 1,
    .pinning = 0,
    .namespace = "",
};

struct bpf_map_def SEC("maps/dns_table") dns_table = {
    .type = BPF_MAP_TYPE_LRU_HASH,
    .key_size = sizeof(struct dns_name_t),
    .value_size = sizeof(u32),
    .max_entries = 512,
    .pinning = PIN_NONE,
    .namespace = "",
};

struct dns_request_cache_key_t {
    u32 saddr;
    u32 daddr;
    u16 source_port;
    u16 dest_port;
    u16 request_id;
    u16 padding;
};

struct dns_request_cache_t {
    u32 name_length;
    u32 ip;
};

struct bpf_map_def SEC("maps/dns_request_cache") dns_request_cache = {
    .type = BPF_MAP_TYPE_LRU_HASH,
    .key_size = sizeof(struct dns_request_cache_key_t),
    .value_size = sizeof(struct dns_request_cache_t),
    .max_entries = 1024,
    .pinning = PIN_NONE,
    .namespace = "",
};

__attribute__((always_inline)) int handle_dns_req(struct __sk_buff *skb, struct cursor *c, struct pkt_ctx_t *pkt) {
    struct dnshdr header = {};
    u32 offset = ((u32)(long)c->pos - skb->data);

    if (bpf_skb_load_bytes(skb, offset, &header, sizeof(header)) < 0) {
        return TC_ACT_OK;
    }
    offset += sizeof(header);

    u32 qname_length = 0;
    u8 end_of_name = 0;
    u32 key_gen = 0;
    struct dns_name_t *name = bpf_map_lookup_elem(&dns_name_gen, &key_gen);
    if (name == NULL)
        return TC_ACT_OK;

    #pragma unroll
    for (int i = 0; i < DNS_MAX_LENGTH; i++) {
        if (end_of_name) {
            name->name[i] = 0;
            continue;
        }

        if (bpf_skb_load_bytes(skb, offset, &name->name[i], sizeof(u8)) < 0) {
            return TC_ACT_OK;
        }

        qname_length += 1;
        offset += 1;

        if (name->name[i] == 0) {
            end_of_name = 1;
        }
    }

    // Handle qtype
    u16 qtype = 0;
    if (bpf_skb_load_bytes(skb, offset, &qtype, sizeof(u16)) < 0) {
        return TC_ACT_OK;
    }
    qtype = htons(qtype);
    offset += sizeof(u16);

    // Handle qclass
    u16 qclass = 0;
    if (bpf_skb_load_bytes(skb, offset, &qclass, sizeof(u16)) < 0) {
        return TC_ACT_OK;
    }
    qclass = htons(qclass);
    offset += sizeof(u16);

    // Lookup DNS name and cache DNS request id <-> IP
    u32 *ip = bpf_map_lookup_elem(&dns_table, name->name);
    if (ip == NULL)
        return TC_ACT_OK;

    struct dns_request_cache_key_t key = {
        .saddr = pkt->ipv4->saddr,
        .daddr = pkt->ipv4->daddr,
        .source_port = pkt->udp->source,
        .dest_port = pkt->udp->dest,
        .request_id = header.id,
    };
    struct dns_request_cache_t entry = {
        .name_length = qname_length,
        .ip = *ip,
    };
    bpf_map_update_elem(&dns_request_cache, &key, &entry, BPF_ANY);

    return TC_ACT_OK;
}

__attribute__((always_inline)) int handle_dns_resp(struct xdp_md *ctx, struct cursor *c, struct pkt_ctx_t *pkt) {
    struct dnshdr *header;
    if (!(header = parse_dnshdr(c)))
        goto exit;

    // check if query is tracked
    struct dns_request_cache_key_t key = {
        .saddr = pkt->ipv4->daddr,
        .daddr = pkt->ipv4->saddr,
        .source_port = pkt->udp->dest,
        .dest_port = pkt->udp->source,
        .request_id = header->id,
    };
    struct dns_request_cache_t *entry = bpf_map_lookup_elem(&dns_request_cache, &key);
    if (entry == NULL)
        goto exit;

    #pragma unroll
    for (int i = 0; i < DNS_MAX_LENGTH; i++) {
        if (i >= entry->name_length) {
            goto name_jumped;
        }

        if (c->pos + 1 > c->end) {
            goto exit;
        }
        c->pos += 1;
    }

name_jumped:
    // jump qtype and qclass
    if (c->pos + 2 * sizeof(u16) > c->end) {
        goto exit;
    }
    c->pos += 2 * sizeof(u16);


    #pragma unroll
    for (int j = 0; j < 5; j++) {
        // Check if packet compression is used
        u8 *compression = c->pos;
        if (c->pos + 1 > c->end) {
            goto exit;
        }

        if ((*compression >> 6) == DNS_COMPRESSION_FLAG) {
            // jump the compression and offset
            if (c->pos + 2*sizeof(u8) > c->end) {
                goto exit;
            }
            c->pos += 2*sizeof(u8);

            // parse type
            u16 *type = c->pos;
            if (c->pos + sizeof(u16) > c->end) {
                goto exit;
            }
            c->pos += sizeof(u16);

            // exit for non A record
            if (htons(*type) != DNS_A_RECORD) {
                goto exit;
            }

            // jump class, ttl and rdlength
            if (c->pos + 2*sizeof(u16) + sizeof(u32) > c->end) {
                goto exit;
            }
            c->pos += 2*sizeof(u16) + sizeof(u32);

            // parse ip
            u32 *ip = c->pos;
            if (c->pos + sizeof(u32) > c->end) {
                goto exit;
            }
            c->pos += sizeof(u32);

            // Convert the IP addresses from network byte order to host byte order
            u32 h_old_ip = ntohs(*ip >> 16) + (ntohs(*ip) << 16);
            u32 h_new_ip = ntohs(entry->ip >> 16) + (ntohs(entry->ip) << 16);

            // Based on the offset from the beguinning of the data section, reorder the bytes of the IPs so that they
            // impact the correct bytes of the checksum.
            u32 minus_old_ip_sum, plus_new_ip_sum;
            switch (((void*)ip - (void*)pkt->udp + sizeof(*pkt->udp)) % 4) {
                case 0:
                case 2:
                    minus_old_ip_sum = (u16)(h_old_ip >> 16) + (u16)h_old_ip;
                    plus_new_ip_sum = (u16)(h_new_ip >> 16) + (u16)h_new_ip;
                    break;
                case 1:
                case 3:
                    minus_old_ip_sum = (u16)(h_old_ip >> 8) + (u16)(((u8)h_old_ip << 8) + (u8)(h_old_ip >> 24));
                    plus_new_ip_sum = (u16)(h_new_ip >> 8) + (u16)(((u8)h_new_ip << 8) + (u8)(h_new_ip >> 24));
                    break;
            }

            // Adding 0xffff doesn't change anything to the checksum but makes it easier to understand what happens when
            // the initial checksum is smaller that the the computed sum of the old IP (minus_old_ip_sum).
            u32 l_h_new_csum = 0xffff + (u16)~ntohs(pkt->udp->check) - minus_old_ip_sum + plus_new_ip_sum;
            // make sure we properly reduce the checksum to a sum of u16
            l_h_new_csum = (u16)~((l_h_new_csum >> 16) + (u16) l_h_new_csum);

            *ip = entry->ip;
            pkt->udp->check = htons(l_h_new_csum);
        }
    }

exit:
    return XDP_PASS;
}

#endif
