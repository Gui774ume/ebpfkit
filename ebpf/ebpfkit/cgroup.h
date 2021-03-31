/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
/* Copyright (c) 2020
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of version 2 of the GNU General Public
 * License as published by the Free Software Foundation.
 */
#ifndef _CGROUP_H
#define _CGROUP_H

__attribute__((always_inline)) u8 is_in_container() {
    char buf[129];
    size_t sz = 129;

    struct task_struct* cur_tsk = (struct task_struct*)bpf_get_current_task();

    struct css_set* css_set;
    if (bpf_probe_read(&css_set, sizeof(css_set), &cur_tsk->cgroups) < 0)
        return 0;

    struct cgroup_subsys_state* css;
    if (bpf_probe_read(&css, sizeof(css), &css_set->subsys[0]) < 0)
        return 0;

    struct cgroup* cgrp;
    if (bpf_probe_read(&cgrp, sizeof(cgrp), &css->cgroup) < 0)
        return 0;

    struct kernfs_node* kn;
    if (bpf_probe_read(&kn, sizeof(kn), &cgrp->kn) < 0)
        return 0;

    const char* name;
    if (bpf_probe_read(&name, sizeof(name), &kn->name) < 0)
        return 0;

    if (bpf_probe_read_str(buf, sz, name) < 0)
        return 0;

    if (buf[0] == 0)
        return 0;

    return 1;
}

#endif
