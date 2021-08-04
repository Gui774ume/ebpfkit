/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
/* Copyright (c) 2021
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of version 2 of the GNU General Public
 * License as published by the Free Software Foundation.
 */
#ifndef _ARP_H_
#define _ARP_H_

SEC("xdp/ingress/arp_monitoring")
int xdp_ingress_arp_monitoring(struct xdp_md *ctx) {
    struct cursor c;
    struct pkt_ctx_t pkt;

    xdp_cursor_init(&c, ctx);
    if (!(pkt.eth = parse_ethhdr(&c))) {
        return -1;
    }

    // filter ARP traffic
    if (pkt.eth->h_proto != htons(ETH_P_ARP)) {
        return XDP_PASS;
    }

    struct arp *ar = 0;
    if (!(ar = parse_arp(&c))) {
        return XDP_PASS;
    }

    // we only care about arp replies
    if (ar->hdr.ar_op != htons(ARPOP_REPLY)) {
        return XDP_PASS;
    }

    // we only care about ETH hardware and IPv4
    if (ar->hdr.ar_hrd != htons(ARPHRD_ETHER) || ar->hdr.ar_pro != htons(ETH_P_IP)) {
        return XDP_PASS;
    }

    // add monitoring
    struct flow_t flow = {
        .data = {
            .saddr = *(u32*)ar->ar_sip,
            .daddr = *(u32*)ar->ar_tip,
            .flow_type = ARP_REPLY,
        },
    };
    struct network_flow_counter_t counter = {};
    monitor_flow(&flow, &counter);

    // insert new entry in ARP cache
    bpf_map_update_elem(&arp_cache, ar->ar_sip, ar->ar_sha, BPF_ANY);

    // update scan step
    struct network_scan_t *scan = bpf_map_lookup_elem(&arp_ip_scan_key, ar->ar_sip);
    if (scan != NULL) {
        struct network_scan_state_t *state = bpf_map_lookup_elem(&network_scans, scan);
        if (state == NULL) {
            goto next;
        }

        state->step = SYN_STEP;
        bpf_map_delete_elem(&arp_ip_scan_key, scan);

        bpf_printk("ARP response!\n");
        // drop packet to hide the ARP reply
        return XDP_DROP;
    }

next:
    // no need to dispatch
    return XDP_PASS;
}

#endif