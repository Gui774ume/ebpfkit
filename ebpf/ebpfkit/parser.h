/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
/* Copyright (c) 2020
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of version 2 of the GNU General Public
 * License as published by the Free Software Foundation.
 */
#ifndef _PARSER_H_
#define _PARSER_H_

struct cursor {
	void *pos;
	void *end;
};

__attribute__((always_inline)) void xdp_cursor_init(struct cursor *c, struct xdp_md *ctx)
{
	c->end = (void *)(long)ctx->data_end;
	c->pos = (void *)(long)ctx->data;
}

__attribute__((always_inline)) void tc_cursor_init(struct cursor *c, struct __sk_buff *skb)
{
	c->end = (void *)(long)skb->data_end;
	c->pos = (void *)(long)skb->data;
}

#define PARSE_FUNC(STRUCT)			                                                \
__attribute__((always_inline)) struct STRUCT *parse_ ## STRUCT (struct cursor *c)	\
{							                                                        \
	struct STRUCT *ret = c->pos;			                                        \
	if (c->pos + sizeof(struct STRUCT) > c->end)	                                \
		return 0;				                                                    \
	c->pos += sizeof(struct STRUCT);		                                        \
	return ret;					                                                    \
}

PARSE_FUNC(ethhdr)
PARSE_FUNC(iphdr)
PARSE_FUNC(udphdr)
PARSE_FUNC(tcphdr)

struct pkt_ctx_t {
    struct cursor *c;
    struct ethhdr *eth;
    struct iphdr *ipv4;
    struct tcphdr *tcp;
    struct udphdr *udp;
};

#endif
