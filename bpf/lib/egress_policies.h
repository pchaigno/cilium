/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */

#ifndef __LIB_EGRESS_POLICIES_H_
#define __LIB_EGRESS_POLICIES_H_

#include "identity.h"
#include "maps.h"

#if defined(ENABLE_EGRESS_GATEWAY) || defined(ENABLE_SRV6)
/* is_cluster_destination returns true if the given destination is part of the
 * cluster. It uses the ipcache and endpoint maps information.
 * We check three cases:
 *  - Remote endpoints (non-zero tunnel endpoint field in ipcache)
 *  - Cilium-managed node (remote or local)
 *  - Local endpoint (present in endpoint map)
 * Everything else is outside the cluster.
 */
# define IS_CLUSTER_DESTINATION(NAME, TYPE, LOOKUP_FN)	\
static __always_inline bool				\
NAME(TYPE ip, __u32 dst_id, __u32 tunnel_endpoint)	\
{							\
	if (tunnel_endpoint != 0)			\
		return true;				\
							\
	if (identity_is_node(dst_id))			\
		return true;				\
							\
	if (LOOKUP_FN(ip))				\
		return true;				\
							\
	return false;					\
}

# ifdef ENABLE_IPV4
IS_CLUSTER_DESTINATION(is_cluster_destination4, struct iphdr *, lookup_ip4_endpoint)
# endif /* ENABLE_IPV4 */
IS_CLUSTER_DESTINATION(is_cluster_destination6, struct ipv6hdr *, lookup_ip6_endpoint)
#endif /* ENABLE_EGRESS_GATEWAY || ENABLE_SRV6 */

#ifdef ENABLE_EGRESS_GATEWAY
/* EGRESS_STATIC_PREFIX represents the size in bits of the static prefix part of
 * an egress policy key (i.e. the source IP).
 */
#define EGRESS_STATIC_PREFIX (sizeof(__be32) * 8)
#define EGRESS_PREFIX_LEN(PREFIX) (EGRESS_STATIC_PREFIX + (PREFIX))
#define EGRESS_IPV4_PREFIX EGRESS_PREFIX_LEN(32)

static __always_inline struct egress_gw_policy_entry *
lookup_ip4_egress_gw_policy(__be32 saddr, __be32 daddr)
{
	struct egress_gw_policy_key key = {
		.lpm_key = { EGRESS_IPV4_PREFIX, {} },
		.saddr = saddr,
		.daddr = daddr,
	};
	return map_lookup_elem(&EGRESS_POLICY_MAP, &key);
}

#endif /* ENABLE_EGRESS_GATEWAY */
#endif /* __LIB_EGRESS_POLICIES_H_ */
