/*
 * MPLS label injection iptables/ip6tables target
 * (C) 2018 by Vadim Fedorenko <vadimjunk@gmail.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt
#include <linux/module.h>
#include <linux/skbuff.h>
#include <linux/mpls.h>
#include <net/mpls.h>
#include <linux/ip.h>
#include <linux/ipv6.h>

#include <linux/netfilter/x_tables.h>
#include "ipt_MARKMPLS.h"

static inline struct mpls_shim_hdr mpls_entry_encode(__u32 label, unsigned ttl, unsigned tc, bool bos)
{
	struct mpls_shim_hdr result;
	result.label_stack_entry =
		__cpu_to_be32((label << MPLS_LS_LABEL_SHIFT) |
			    (tc << MPLS_LS_TC_SHIFT) |
			    (bos ? (1 << MPLS_LS_S_SHIFT) : 0) |
			    (ttl << MPLS_LS_TTL_SHIFT));
	return result;
}
static unsigned int
markmpls_tg(struct sk_buff *skb, const struct xt_action_param *par)
{
	struct mpls_shim_hdr *hdr;
	struct net_device *out_dev;
	struct dst_entry *dst = skb_dst(skb);
	__u32 ttl;
	__u32 mark = skb->mark & 0x000FFFFF;

	/* Do not set MPLS without route desition */
	if (!dst) {
		pr_devel("No output route information\n");
		return XT_CONTINUE;
	}
	/* Do not update skb without mark */
	if (!mark)
		return XT_CONTINUE;
	/* Do not set MPLS label for not IP packets */
	if (skb->protocol != htons(ETH_P_IP))
		return XT_CONTINUE;

	if (!skb_make_writable(skb, skb->len))
		return NF_DROP;
	skb_forward_csum(skb);
	if (dst->ops->family == AF_INET) {
		ttl = ip_hdr(skb)->ttl;
	} else if (dst->ops->family == AF_INET6) {
		ttl = ipv6_hdr(skb)->hop_limit;
	} else
		return NF_DROP;
	
	/* Ensure there is enough space for the headers in the skb */
	if (skb_cow(skb, sizeof(struct mpls_shim_hdr)));
		return NF_DROP;

	skb_set_inner_protocol(skb, skb->protocol);
	skb_reset_inner_network_header(skb);

	skb_push(skb, sizeof(struct mpls_shim_hdr));

	skb_reset_network_header(skb);

	skb->dev = out_dev;
	skb->protocol = htons(ETH_P_MPLS_UC);

	/* Push the label */
	hdr = mpls_hdr(skb);
	*hdr = mpls_entry_encode(mark, ttl, 0, true);
	return XT_CONTINUE;
}

static int markmpls_tg_check(const struct xt_tgchk_param *par)
{
	if ((par->hook_mask & ~(1 << NF_INET_POST_ROUTING)) != 0) {
		pr_info("Only possible after route decision\n");
		return -EINVAL;
	}		
	return 0;
}

static struct xt_target markmpls_tg_reg[] __read_mostly = {
	{
		.name       = "MARKMPLS",
		.revision   = 0,
		.family     = NFPROTO_IPV4,
		.target     = markmpls_tg,
		.targetsize = 0,
		.table      = "mangle",
		.checkentry = markmpls_tg_check,
		.me         = THIS_MODULE,
	},
	{
		.name       = "MARKMPLS",
		.revision   = 0,
		.family     = NFPROTO_IPV6,
		.target     = markmpls_tg,
		.targetsize = 0,
		.table      = "mangle",
		.checkentry = markmpls_tg_check,
		.me         = THIS_MODULE,
	},
};

static int __init markmpls_tg_init(void)
{
	return xt_register_targets(markmpls_tg_reg, ARRAY_SIZE(markmpls_tg_reg));
}

static void __exit markmpls_tg_exit(void)
{
	xt_unregister_targets(markmpls_tg_reg, ARRAY_SIZE(markmpls_tg_reg));
}

module_init(markmpls_tg_init);
module_exit(markmpls_tg_exit);
MODULE_AUTHOR("Vadim Fedorenko <vadimjunk@gmail.com>");
MODULE_DESCRIPTION("Xtables: Move skb->mark to MPLS label");
MODULE_LICENSE("GPL");
MODULE_ALIAS("ipt_MPLS");
MODULE_ALIAS("ip6t_MPLS");
