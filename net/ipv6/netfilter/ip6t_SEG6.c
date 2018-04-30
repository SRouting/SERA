/* IPv6 Segment Routing target module (SEG6).
 *
 * Author:
 * Ahmed Abdelsalam <amsalam20@gmail.com>
 *
 *  This program is free software; you can redistribute it and/or
 *	modify it under the terms of the GNU General Public License
 *	as published by the Free Software Foundation; either version 2
 *	of the License, or (at your option) any later version.
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/gfp.h>
#include <linux/module.h>
#include <linux/skbuff.h>
#include <linux/icmpv6.h>
#include <linux/netdevice.h>
#include <linux/netfilter/x_tables.h>
#include <linux/netfilter_ipv6/ip6_tables.h>
#include <linux/netfilter_ipv6/ip6t_SEG6.h>

#include <net/flow.h>
#include <net/seg6.h>
#include <net/ip6_route.h>

static int seg6_go_next(struct sk_buff *skb, struct ipv6_sr_hdr *srh)
{
	if (srh->segments_left == 0)
		return NF_DROP;
	seg6_advance_nextseg(srh, &ipv6_hdr(skb)->daddr);
	seg6_lookup_nexthop(skb, NULL, 0);
	dst_input(skb);
	return NF_STOLEN;
}

static int seg6_skip_next(struct sk_buff *skb, struct ipv6_sr_hdr *srh)
{
	if (srh->segments_left < 2)
		return NF_DROP;
	seg6_advance_nextseg(srh, &ipv6_hdr(skb)->daddr);
	seg6_advance_nextseg(srh, &ipv6_hdr(skb)->daddr);
	seg6_lookup_nexthop(skb, NULL, 0);
	dst_input(skb);
	return NF_STOLEN;
}

static int seg6_go_last(struct sk_buff *skb, struct ipv6_sr_hdr *srh)
{
	if (srh->segments_left == 0)
		return NF_DROP;
	srh->segments_left = 1;
	seg6_advance_nextseg(srh, &ipv6_hdr(skb)->daddr);
	seg6_lookup_nexthop(skb, NULL, 0);
	dst_input(skb);
	return NF_STOLEN;
}

static unsigned int
seg6_tg6(struct sk_buff *skb, const struct xt_action_param *par)
{
	struct ipv6_sr_hdr *srh;
	const struct ip6t_seg6_info *seg6 = par->targinfo;

	srh = seg6_get_srh(skb);
	if (!srh)
		return NF_DROP;

	switch (seg6->action) {
	case IP6T_SEG6_GO_NEXT:
		return seg6_go_next(skb, srh);
	case IP6T_SEG6_SKIP_NEXT:
		return seg6_skip_next(skb, srh);
	case IP6T_SEG6_GO_LAST:
		return seg6_go_last(skb, srh);
	}
	pr_err("Unknown SEG6 action\n");
	return NF_DROP;
}

static int seg6_check(const struct xt_tgchk_param *par)
{
	/**
	 * In the future, some new action may require using this function
	 */
	return 0;
}

static struct xt_target seg6_tg6_reg __read_mostly = {
	.name		= "SEG6",
	.family		= NFPROTO_IPV6,
	.target		= seg6_tg6,
	.targetsize	= sizeof(struct ip6t_seg6_info),
	.checkentry	= seg6_check,
	.me		= THIS_MODULE
};

static int __init seg6_tg6_init(void)
{
	return xt_register_target(&seg6_tg6_reg);
}

static void __exit seg6_tg6_exit(void)
{
	xt_unregister_target(&seg6_tg6_reg);
}

module_init(seg6_tg6_init);
module_exit(seg6_tg6_exit);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Xtables: IPv6 Segment Routing Target (SEG6)");
MODULE_AUTHOR("Ahmed Abdelsalam <amsalam20@gmail.com>");
