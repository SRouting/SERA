#ifndef _IP6T_SRH_H
#define _IP6T_SRH_H

#include <linux/types.h>
#include <linux/netfilter.h>

/* Values for "mt_flags" field in struct ip6t_srh */
#define IP6T_SRH_NEXTHDR        0x0001
#define IP6T_SRH_LEN_EQ         0x0002
#define IP6T_SRH_LEN_GT         0x0004
#define IP6T_SRH_LEN_LT         0x0008
#define IP6T_SRH_SEGS_EQ        0x0010
#define IP6T_SRH_SEGS_GT        0x0020
#define IP6T_SRH_SEGS_LT        0x0040
#define IP6T_SRH_LAST_EQ        0x0080
#define IP6T_SRH_LAST_GT        0x0100
#define IP6T_SRH_LAST_LT        0x0200
#define IP6T_SRH_TAG            0x0400
#define IP6T_SRH_PSID           0x0800
#define IP6T_SRH_NSID           0x1000
#define IP6T_SRH_MASK           0x1FFF

/* Values for "mt_invflags" field in struct ip6t_srh */
#define IP6T_SRH_INV_NEXTHDR    0x0001
#define IP6T_SRH_INV_LEN_EQ     0x0002
#define IP6T_SRH_INV_LEN_GT     0x0004
#define IP6T_SRH_INV_LEN_LT     0x0008
#define IP6T_SRH_INV_SEGS_EQ    0x0010
#define IP6T_SRH_INV_SEGS_GT    0x0020
#define IP6T_SRH_INV_SEGS_LT    0x0040
#define IP6T_SRH_INV_LAST_EQ    0x0080
#define IP6T_SRH_INV_LAST_GT    0x0100
#define IP6T_SRH_INV_LAST_LT    0x0200
#define IP6T_SRH_INV_TAG        0x0400
#define IP6T_SRH_INV_PSID       0x0800
#define IP6T_SRH_INV_NSID       0x1000
#define IP6T_SRH_INV_MASK       0x1FFF

/**
 *      struct ip6t_srh - SRH match options
 *      @ next_hdr: Next header field of SRH
 *      @ hdr_len: Extension header length field of SRH
 *      @ segs_left: Segments left field of SRH
 *      @ last_entry: Last entry field of SRH
 *      @ tag: Tag field of SRH
 *      @ psid: SRH previous SID
 *      @ pmsk: SRH previous SID mask
 *      @ nsid: SRH next SID
 *      @ nmsk: SRH next SID mask
 *      @ mt_flags: match options
 *      @ mt_invflags: Invert the sense of match options
 */

struct ip6t_srh {
	__u8                    next_hdr;
	__u8                    hdr_len;
	__u8                    segs_left;
	__u8                    last_entry;
	__u16                   tag;
	struct in6_addr		psid;
	struct in6_addr         pmsk;
	struct in6_addr         nsid;
	struct in6_addr         nmsk;
	__u16                   mt_flags;
	__u16                   mt_invflags;
};

#endif /*_IP6T_SRH_H*/
