/*
 * Modifications copyright (C) 2011 Battelle Memorial Institute
 *
 * Licensed under the GNU General Public License Version 2.
 * See LICENSE for the full text of the license.
 * See DISCLAIMER for additional disclaimers.
 * 
 * Author: Brandon Carpenter
 */

/*
 * The following code was conveniently borrowed form the xt_socket
 * iptables module and used with minor modifications.  Thanks guys!
 *
 * Transparent proxy support for Linux/iptables
 *
 * Copyright (C) 2007-2008 BalaBit IT Ltd.
 * Author: Krisztian Kovacs
 */

#include <linux/version.h>
#include <linux/skbuff.h>
#include <net/tcp.h>
#include <net/udp.h>
#include <net/icmp.h>
#include <net/sock.h>
#include <net/inet_sock.h>

#if defined(CONFIG_IPV6) || defined(CONFIG_IPV6_MODULE)
#include <net/ipv6.h>
#include <net/inet6_hashtables.h>
#endif

#if defined(CONFIG_NF_CONNTRACK) || defined(CONFIG_NF_CONNTRACK_MODULE)
#define XT_SOCKET_HAVE_CONNTRACK 1
#include <net/netfilter/nf_conntrack.h>
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,33)
#define inet_rcv_saddr rcv_saddr
#endif

static void put_sock(struct sock *sk)
{
	if (sk->sk_state == TCP_TIME_WAIT)
		inet_twsk_put(inet_twsk(sk));
	else
		sock_put(sk);
}

static int extract_icmp4_fields(const struct sk_buff *skb, u8 *protocol,
		__be32 *raddr, __be32 *laddr, __be16 *rport, __be16 *lport)
{
	unsigned int outside_hdrlen = ip_hdrlen(skb);
	struct iphdr *inside_iph, _inside_iph;
	struct icmphdr *icmph, _icmph;
	__be16 *ports, _ports[2];

	icmph = skb_header_pointer(skb, outside_hdrlen,
				   sizeof(_icmph), &_icmph);
	if (icmph == NULL)
		return 1;

	switch (icmph->type) {
	case ICMP_DEST_UNREACH:
	case ICMP_SOURCE_QUENCH:
	case ICMP_REDIRECT:
	case ICMP_TIME_EXCEEDED:
	case ICMP_PARAMETERPROB:
		break;
	default:
		return 1;
	}

	inside_iph = skb_header_pointer(skb, outside_hdrlen +
					sizeof(struct icmphdr),
					sizeof(_inside_iph), &_inside_iph);
	if (inside_iph == NULL)
		return 1;

	if (inside_iph->protocol != IPPROTO_TCP &&
	    inside_iph->protocol != IPPROTO_UDP)
		return 1;

	ports = skb_header_pointer(skb, outside_hdrlen +
				   sizeof(struct icmphdr) +
				   (inside_iph->ihl << 2),
				   sizeof(_ports), &_ports);
	if (ports == NULL)
		return 1;

	/* the inside IP packet is the one quoted from our side, thus
	 * its saddr is the local address */
	*protocol = inside_iph->protocol;
	*laddr = inside_iph->saddr;
	*lport = ports[0];
	*raddr = inside_iph->daddr;
	*rport = ports[1];

	return 0;
}

static struct sock *lookup_v4_sock(const struct sk_buff *skb,
		const struct net_device *indev)
{
	struct iphdr *iph = ip_hdr(skb);
	struct udphdr _hdr, *hp = NULL;
	struct sock *sk;
	__be32 daddr = 0, saddr = 0;
	__be16 dport = 0, sport = 0;
	u8 protocol = 0;
#ifdef XT_SOCKET_HAVE_CONNTRACK
	struct nf_conn const *ct;
	enum ip_conntrack_info ctinfo;
#endif

	if (iph->protocol == IPPROTO_UDP || iph->protocol == IPPROTO_TCP) {
		hp = skb_header_pointer(skb, ip_hdrlen(skb),
					sizeof(_hdr), &_hdr);
		if (hp == NULL)
			return NULL;

		protocol = iph->protocol;
		saddr = iph->saddr;
		sport = hp->source;
		daddr = iph->daddr;
		dport = hp->dest;

	} else if (iph->protocol == IPPROTO_ICMP) {
		if (extract_icmp4_fields(skb, &protocol, &saddr, &daddr,
					&sport, &dport))
			return NULL;
	} else {
		return NULL;
	}

#ifdef XT_SOCKET_HAVE_CONNTRACK
	/* Do the lookup with the original socket address in case this is a
	 * reply packet of an established SNAT-ted connection. */

	ct = nf_ct_get(skb, &ctinfo);
	if (ct &&
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,36)
			!nf_ct_is_untracked(ct) &&
#else
			(ct != &nf_conntrack_untracked) &&
#endif
	    ((iph->protocol != IPPROTO_ICMP &&
	      ctinfo == IP_CT_IS_REPLY + IP_CT_ESTABLISHED) ||
	     (iph->protocol == IPPROTO_ICMP &&
	      ctinfo == IP_CT_IS_REPLY + IP_CT_RELATED)) &&
	    (ct->status & IPS_SRC_NAT_DONE)) {

		daddr = ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.src.u3.ip;
		dport = (iph->protocol == IPPROTO_TCP) ?
			ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.src.u.tcp.port :
			ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.src.u.udp.port;
	}
#endif

	if (protocol == IPPROTO_TCP)
		sk = __inet_lookup(dev_net(skb->dev), &tcp_hashinfo,
				saddr, sport, daddr, dport, indev->ifindex);
	else
		sk = udp4_lib_lookup(dev_net(skb->dev),
				saddr, sport, daddr, dport, indev->ifindex);
	if (!sk)
		return NULL;

	/* Ignore sockets listening on INADDR_ANY */
	if (sk->sk_state != TCP_TIME_WAIT && inet_sk(sk)->inet_rcv_saddr == 0) {
		put_sock(sk);
		return NULL;
	}
	return sk;
}

#if defined(CONFIG_IPV6) || defined(CONFIG_IPV6_MODULE)
#  if LINUX_VERSION_CODE >= KERNEL_VERSION(3,3,2)
#    define SKIPHDR(...) ipv6_skip_exthdr(__VA_ARGS__, NULL)
#  else
#    define SKIPHDR ipv6_skip_exthdr
#  endif

static int extract_icmp6_fields(const struct sk_buff *skb,
		unsigned int outside_hdrlen, int *protocol, struct in6_addr **raddr,
		struct in6_addr **laddr, __be16 *rport, __be16 *lport)
{
	struct ipv6hdr *inside_iph, _inside_iph;
	struct icmp6hdr *icmph, _icmph;
	__be16 *ports, _ports[2];
	u8 inside_nexthdr;
	int inside_hdrlen;

	icmph = skb_header_pointer(skb, outside_hdrlen,
				   sizeof(_icmph), &_icmph);
	if (icmph == NULL)
		return 1;

	if (icmph->icmp6_type & ICMPV6_INFOMSG_MASK)
		return 1;

	inside_iph = skb_header_pointer(skb, outside_hdrlen + sizeof(_icmph), sizeof(_inside_iph), &_inside_iph);
	if (inside_iph == NULL)
		return 1;
	inside_nexthdr = inside_iph->nexthdr;

	inside_hdrlen = SKIPHDR(skb, outside_hdrlen + sizeof(_icmph) + sizeof(_inside_iph), &inside_nexthdr);
	if (inside_hdrlen < 0)
		return 1; /* hjm: Packet has no/incomplete transport layer headers. */

	if (inside_nexthdr != IPPROTO_TCP &&
	    inside_nexthdr != IPPROTO_UDP)
		return 1;

	ports = skb_header_pointer(skb, inside_hdrlen,
				   sizeof(_ports), &_ports);
	if (ports == NULL)
		return 1;

	/* the inside IP packet is the one quoted from our side, thus
	 * its saddr is the local address */
	*protocol = inside_nexthdr;
	*laddr = &inside_iph->saddr;
	*lport = ports[0];
	*raddr = &inside_iph->daddr;
	*rport = ports[1];

	return 0;
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(3,8,0)
int ipv6_find_hdr(const struct sk_buff *skb, unsigned int *offset,
		  int target, unsigned short *fragoff, int *fragflg)
{
	unsigned int start = skb_network_offset(skb) + sizeof(struct ipv6hdr);
	u8 nexthdr = ipv6_hdr(skb)->nexthdr;
	unsigned int len = skb->len - start;

	if (fragoff)
		*fragoff = 0;

	while (nexthdr != target) {
		struct ipv6_opt_hdr _hdr, *hp;
		unsigned int hdrlen;

		if ((!ipv6_ext_hdr(nexthdr)) || nexthdr == NEXTHDR_NONE) {
			if (target < 0)
				break;
			return -ENOENT;
		}

		hp = skb_header_pointer(skb, start, sizeof(_hdr), &_hdr);
		if (hp == NULL)
			return -EBADMSG;
		if (nexthdr == NEXTHDR_FRAGMENT) {
			unsigned short _frag_off;
			__be16 *fp;
			fp = skb_header_pointer(skb,
						start+offsetof(struct frag_hdr,
							       frag_off),
						sizeof(_frag_off),
						&_frag_off);
			if (fp == NULL)
				return -EBADMSG;

			_frag_off = ntohs(*fp) & ~0x7;
			if (_frag_off) {
				if (target < 0 &&
				    ((!ipv6_ext_hdr(hp->nexthdr)) ||
				     hp->nexthdr == NEXTHDR_NONE)) {
					if (fragoff)
						*fragoff = _frag_off;
					return hp->nexthdr;
				}
				return -ENOENT;
			}
			hdrlen = 8;
		} else if (nexthdr == NEXTHDR_AUTH)
			hdrlen = (hp->hdrlen + 2) << 2;
		else
			hdrlen = ipv6_optlen(hp);

		nexthdr = hp->nexthdr;
		len -= hdrlen;
		start += hdrlen;
	}

	*offset = start;
	return nexthdr;
}
#endif /* LINUX_VERSION_CODE < KERNEL_VERSION(3,8,0) */

#  if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,37)
extern struct sock *__udp6_lib_lookup(struct net *net,
				      struct in6_addr *saddr, __be16 sport,
				      struct in6_addr *daddr, __be16 dport,
				      int dif, struct udp_table *udptable);

#define udp6_lib_lookup(net, saddr, sport, daddr, dport, dif) \
	__udp6_lib_lookup((net), (struct in6_addr *) (saddr), (sport), \
			(struct in6_addr *) (daddr), (dport), (dif), &udp_table)
#  endif

static struct sock *lookup_v6_sock(const struct sk_buff *skb,
			const struct net_device *indev)
{
	struct ipv6hdr *iph = ipv6_hdr(skb);
	struct udphdr _hdr, *hp = NULL;
	struct sock *sk;
	struct in6_addr *daddr, *saddr;
	__be16 dport, sport;
	int thoff = 0, tproto;

	tproto = ipv6_find_hdr(skb, &thoff, -1, NULL, NULL);
	if (tproto < 0)
		// unable to find transport header in IPv6 packet
		return NULL;

	if (tproto == IPPROTO_UDP || tproto == IPPROTO_TCP) {
		hp = skb_header_pointer(skb, thoff,
					sizeof(_hdr), &_hdr);
		if (hp == NULL)
			return NULL;

		saddr = &iph->saddr;
		sport = hp->source;
		daddr = &iph->daddr;
		dport = hp->dest;

	} else if (tproto == IPPROTO_ICMPV6) {
		if (extract_icmp6_fields(skb, thoff, &tproto, &saddr, &daddr,
					 &sport, &dport))
			return NULL;
	} else {
		return NULL;
	}

	if (tproto == IPPROTO_TCP)
		sk = inet6_lookup(dev_net(skb->dev), &tcp_hashinfo,
				saddr, sport, daddr, dport, indev->ifindex);
	else
		sk = udp6_lib_lookup(dev_net(skb->dev),
				saddr, sport, daddr, dport, indev->ifindex);
	if (!sk)
		return NULL;


	/* Ignore sockets listening on INADDR_ANY */
	if (sk->sk_state != TCP_TIME_WAIT && inet_sk(sk)->inet_rcv_saddr == 0) {
		put_sock(sk);
		return NULL;
	}
	return sk;
}
#endif

