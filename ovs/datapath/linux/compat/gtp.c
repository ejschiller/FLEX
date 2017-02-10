/*
 * Copyright (c) 2015 Nicira, Inc.
 * Copyright (c) 2013 Cisco Systems, Inc.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of version 2 of the GNU General Public
 * License as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * General Public License for more details.
 *
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/version.h>

#include <linux/etherdevice.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/net.h>
#include <linux/module.h>
#include <linux/rculist.h>
#include <linux/udp.h>

#include <net/icmp.h>
#include <net/ip.h>
#include <net/gtp.h>
#include <net/net_namespace.h>
#include <net/netns/generic.h>
#include <net/route.h>
#include <net/udp.h>
#include <net/udp_tunnel.h>
#include <net/xfrm.h>

#include "datapath.h"
#include "gso.h"
#include "vport.h"
#include "gso.h"
#include "vport-netdev.h"

#define GTP_UDP_PORT		2152
#define GTP_NETDEV_VER		"0.1"
static int gtp_net_id;

/* Pseudo network device */
struct gtp_dev {
    struct net         *net;        /* netns for packet i/o */
    struct net_device  *dev;        /* netdev for gtp tunnel */
    struct socket      *sock;
    __be16             dst_port;
    struct list_head   next;
};

/* per-network namespace private data for this module */
struct gtp_net {
    struct list_head gtp_list;
};

/*
 *  GTP encapsulation header:
 *
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |  V  |P|R|E|S|N|  Message Type |        Total Length           |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |                           TEID                                |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |      Sequence Number          | N-PDU Number  | Next Extension|
 *  |                               |               |  Header type  |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 * Extension Header:
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |  Total length |                 Contents                      |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |                          Contents                             |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |                   Contents                  | Next Extntn hdr |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */

/**
 * struct gtphdr - GTP header:
 *
 * @version(V): 3-bit field. For GTPv1, this has a value of 1.
 * @protocol_type(P): a 1-bit value that differentiates GTP (value 1) from
 *                    GTP' (value 0).
 * @reserved(R): a 1-bit reserved field (must be 0).
 * @extension_header_flag(E): a 1-bit value that states whether there is an
 *                            extension header optional field.
 * @sequence_number_flag(S): a 1-bit value that states whether there is a
 *                           Sequence Number optional field.
 * @n_pdu_number_flag(N): a 1-bit value that states whether there is a N-PDU
 *                        number optional field.
 * @message_type: an 8-bit field that indicates the type of GTP message.
 * @total_length: a 16-bit field that indicates the length of the payload in
 *                bytes (rest of the packet following the mandatory 8-byte GTP
 *                header). Includes the optional fields.
 * @teid: A 32-bit(4-octet) field used to multiplex different connections in
          the same GTP tunnel.
 * @sequence_number: an (optional) 16-bit field. This field exists if any of the
 *                   E, S, or PN bits are on. The field must be interpreted only
 *                   if the S bit is on.
 * @n_pdu_number: an (optional) 8-bit field. This field exists if any of the E,
 *                S, or PN bits are on. The field must be interpreted only if
 *                the PN bit is on.
 * @next_extension_header_type: an (optional) 8-bit field. This field exists if
 *                              any of the E, S, or PN bits are on. The field
 *                              must be interpreted only if the E bit is on.
 *
 * Extenstion header:
 * @length: an 8-bit field. This field states the length of this extension
 *          header, including the length, the contents, and the next extension
 *          header field, in 4-octet units, so the length of the extension must
 *          always be a multiple of 4.
 * @contents: extension header contents.
 * @next_extension_header: an 8-bit field. It states the type of the next
 *                         extension, or 0 if no next extension exists. This
 *                         permits chaining several next extension headers.
 */

struct gtp_extension_hdr {
    u8 length;
    u8 next_extension_hdr_type;
    u8 extension_data[];
};

struct gtphdr {
#ifdef __LITTLE_ENDIAN_BITFIELD
    __u8 n_pdu_number_flag:1;
    __u8 sequence_hdr_flag:1;
    __u8 extension_hdr_flag:1;
    __u8 reserved:1;
    __u8 protocol_type:1;
    __u8 version:2;
#else
    __u8 version:2;
    __u8 protocol_type:1;
    __u8 reserved:1;
    __u8 extension_hdr_flag:1;
    __u8 sequence_hdr_flag:1;
    __u8 n_pdu_number_flag:1;
#endif
    __u8 message_type;
    __be16 total_length;
    __be32 teid;
    struct gtp_extension_hdr extensions[];
};

#define GTP_HLEN (sizeof(struct udphdr) + sizeof(struct gtphdr))
#define GTP_MAX_MTU (IP_MAX_MTU - GTP_HLEN - sizeof(struct gtphdr))

static inline struct gtphdr *gtp_hdr(const struct sk_buff *skb)
{
    return (struct gtphdr *)(udp_hdr(skb) + 1);
}

/* Compute source UDP port for outgoing packet.
 * Currently we use the flow hash.
 */
static u16 get_src_port(struct net *net, struct sk_buff *skb)
{
    u32 hash = skb_get_hash(skb);
    unsigned int range;
    int high;
    int low;

    if (!hash) {
        if (skb->protocol == htons(ETH_P_IP)) {
            struct iphdr *iph;
            int size = (sizeof(iph->saddr) * 2) / sizeof(u32);

            iph = (struct iphdr *) skb_network_header(skb);
            hash = jhash2((const u32 *)&iph->saddr, size, 0);
        } else if (skb->protocol == htons(ETH_P_IPV6)) {
            struct ipv6hdr *ipv6hdr;

            ipv6hdr = (struct ipv6hdr *) skb_network_header(skb);
            hash = jhash2((const u32 *)&ipv6hdr->saddr,
                          (sizeof(struct in6_addr) * 2) / sizeof(u32), 0);
        } else {
            pr_warn_once("GTP inner protocol is not IP when "
                         "calculating hash.\n");
        }
    }

    inet_get_local_port_range(net, &low, &high);
    range = (high - low) + 1;
    return (((u64) hash * range) >> 32) + low;
}

static void gtp_build_header(struct sk_buff *skb,
                             const struct ip_tunnel_key *tun_key)
{
    struct gtphdr *gtph;

    gtph = (struct gtphdr *)__skb_push(skb, sizeof(struct gtphdr));
    gtph->version = 1;       /* GTP-U version 1 */
    gtph->protocol_type = 1; /* GTP Protocol */
    gtph->reserved = 0;    /* Reserved flags, set to 0  */
    gtph->extension_hdr_flag = 0; /* No extension header present */
    gtph->sequence_hdr_flag = 0; /* No Sequence No. present  */
    gtph->n_pdu_number_flag = 0;      /* No N PDU present */
    gtph->message_type = 255; /* GPDU Packets */
    /* mandatory part of GTP header first 8 octets */
    gtph->total_length = htons(skb->len) - htons(sizeof(struct gtphdr));
    gtph->teid = htonl(be64_to_cpu(tun_key->tun_id));
}

/* Called with rcu_read_lock and BH disabled. */
static int gtp_rcv(struct sock *sk, struct sk_buff *skb)
{
	struct gtp_dev *gtp_dev;
    struct net_device *dev;
    struct gtphdr *gtph;
    struct iphdr *inner_iph;
    struct metadata_dst *tun_dst;
#ifndef USE_UPSTREAM_TUNNEL
    struct metadata_dst temp;
#endif
    __be64 key;
    struct ethhdr *ethh;
    __be16 protocol;

    dev = rcu_dereference_sk_user_data(sk);
    if (unlikely(!dev))
        goto error;
	gtp_dev = netdev_priv(dev);
    if (iptunnel_pull_header(skb, GTP_HLEN, 0,!net_eq(gtp_dev->net, dev_net(gtp_dev->dev))))
        goto error;

    gtph = gtp_hdr(skb);

    key = cpu_to_be64(ntohl(gtph->teid));

    /* Save outer tunnel values */
#ifndef USE_UPSTREAM_TUNNEL
    tun_dst = &temp;
    ovs_udp_tun_rx_dst(tun_dst, skb, AF_INET, TUNNEL_KEY, key, 0);
#else
    tun_dst = udp_tun_rx_dst(skb, AF_INET, TUNNEL_KEY, key, 0);
#endif
    /* Drop non-IP inner packets */
    inner_iph = (struct iphdr *)(gtph + 1);
    switch (inner_iph->version) {
    case 4:
        protocol = htons(ETH_P_IP);
        break;
    case 6:
        protocol = htons(ETH_P_IPV6);
        break;
    default:
        goto error;
    }
    skb->protocol = protocol;

    /* Add Ethernet header */
    ethh = (struct ethhdr *)skb_push(skb, ETH_HLEN);
    memset(ethh, 0, ETH_HLEN);
    ethh->h_dest[0] = 0x06;
    ethh->h_source[0] = 0x06;
    ethh->h_proto = protocol;

    ovs_ip_tunnel_rcv(dev, skb, tun_dst);
    goto out;

error:
    kfree_skb(skb);
out:
    return 0;
}

static struct rtable *gtp_get_rt(struct sk_buff *skb,
				 struct net_device *dev,
				 struct flowi4 *fl,
				 const struct ip_tunnel_key *key)
{
	struct net *net = dev_net(dev);

	/* Route lookup */
	memset(fl, 0, sizeof(*fl));
	fl->daddr = key->u.ipv4.dst;
	fl->saddr = key->u.ipv4.src;
	fl->flowi4_tos = RT_TOS(key->tos);
	fl->flowi4_mark = skb->mark;
	fl->flowi4_proto = IPPROTO_UDP;

	return ip_route_output_key(net, fl);
}

#if !defined(HAVE_UDP_TUNNEL_HANDLE_OFFLOAD_RET_SKB) || !defined(USE_UPSTREAM_TUNNEL)
static struct sk_buff *
__udp_tunnel_handle_offloads(struct sk_buff *skb, bool udp_csum)
{
	int err;

	err = udp_tunnel_handle_offloads(skb, udp_csum);
	if (err) {
		kfree_skb(skb);
		return NULL;
	}
	return skb;
}
#else
#define __udp_tunnel_handle_offloads udp_tunnel_handle_offloads
#endif



netdev_tx_t rpl_gtp_xmit(struct sk_buff *skb)
{
    struct net_device *dev = skb->dev;
    struct gtp_dev *gtp_dev = netdev_priv(dev);
    struct net *net = gtp_dev->net;
    int network_offset = skb_network_offset(skb);
    struct ip_tunnel_info *info;
    struct ip_tunnel_key *tun_key;
    struct rtable *rt;
    int min_headroom;
	struct socket *sock;
    __be16 src_port, dst_port;
    struct flowi4 fl;
    __be16 df;
    int err;

    info = skb_tunnel_info(skb);
    if (unlikely(!info)) {
        err = -EINVAL;
        goto error;
    }
	
	
    sock = rcu_dereference(gtp_dev->sock);
    if (!sock) {
		err = -EIO;
                goto error;
    }	    

    if (skb->protocol != htons(ETH_P_IP) &&
        skb->protocol != htons(ETH_P_IPV6)) {
        err = 0;
        goto error;
    }

    tun_key = &info->key;
	rt = gtp_get_rt(skb,dev,&fl,tun_key);

    if (IS_ERR(rt)) {
        err = PTR_ERR(rt);
        goto error;
    }

    min_headroom = LL_RESERVED_SPACE(rt->dst.dev) + rt->dst.header_len
                   + sizeof(struct iphdr) + GTP_HLEN;

    if (skb_headroom(skb) < min_headroom || skb_header_cloned(skb)) {
        int head_delta = SKB_DATA_ALIGN(min_headroom -
                                        skb_headroom(skb) + 16);

        err = pskb_expand_head(skb, max_t(int, head_delta, 0),
                               0, GFP_ATOMIC);
        if (unlikely(err))
            goto err_free_rt;
    }

    /* Reset l2 headers. */
    skb_pull(skb, network_offset);
    skb_reset_mac_header(skb);
    skb->vlan_tci=0;
	
	
    if (skb_is_gso(skb) && skb_is_encapsulated(skb))
		goto err_free_rt;

    skb = __udp_tunnel_handle_offloads(skb, false);
    if (!skb)
            return NETDEV_TX_OK;

    src_port = htons(get_src_port(net, skb));
    dst_port = gtp_dev->dst_port;

    gtp_build_header(skb, tun_key);

    skb->ignore_df = 1;

    ovs_skb_set_inner_protocol(skb, skb->protocol);

    df = tun_key->tun_flags & TUNNEL_DONT_FRAGMENT ? htons(IP_DF) : 0;
    udp_tunnel_xmit_skb(rt, sock->sk, skb,
                              fl.saddr, tun_key->u.ipv4.dst,
                              tun_key->tos, tun_key->ttl,
                              df, src_port, dst_port, false, true);
    return NETDEV_TX_OK;

err_free_rt:
    ip_rt_put(rt);
error:
    kfree_skb(skb);
    return NETDEV_TX_OK;
}
EXPORT_SYMBOL(rpl_gtp_xmit);

static int gtp_init(struct net_device *dev)
{
	dev->tstats = (typeof(dev->tstats)) netdev_alloc_pcpu_stats(struct pcpu_sw_netstats);
	if (!dev->tstats)
		return -ENOMEM;

	return 0;
}

static void gtp_uninit(struct net_device *dev)
{
	free_percpu(dev->tstats);
}

static struct socket *create_sock(struct net *net, bool ipv6,
                                  __be16 port)
{
    struct socket *sock;
    struct udp_port_cfg udp_conf;
    int err;

    memset(&udp_conf, 0, sizeof(udp_conf));

    if (ipv6) {
        udp_conf.family = AF_INET6;
    } else {
        udp_conf.family = AF_INET;
        udp_conf.local_ip.s_addr = htonl(INADDR_ANY);
    }

    udp_conf.local_udp_port = port;

    /* Open UDP socket */
    err = udp_sock_create(net, &udp_conf, &sock);
    if (err < 0)
        return ERR_PTR(err);

    return sock;
}

static int gtp_open(struct net_device *dev)
{
    struct gtp_dev *gtp = netdev_priv(dev);
    struct udp_tunnel_sock_cfg tunnel_cfg;
    struct net *net = gtp->net;
    struct socket *sock;

    sock = create_sock(net, false, gtp->dst_port);
    if (IS_ERR(gtp->sock))
        return PTR_ERR(gtp->sock);
	
    rcu_assign_pointer(gtp->sock, sock);
    /* Mark socket as an encapsulation socket */
    tunnel_cfg.sk_user_data = dev;
    tunnel_cfg.encap_type = 1;
    tunnel_cfg.encap_rcv = gtp_rcv;
    tunnel_cfg.encap_destroy = NULL;
    setup_udp_tunnel_sock(net, gtp->sock, &tunnel_cfg);
    return 0;
}

static int gtp_stop(struct net_device *dev)
{
    struct gtp_dev *gtp = netdev_priv(dev);
    struct socket *socket;

	socket = rtnl_dereference(gtp->sock);
	if (!socket)
		return 0;

	rcu_assign_pointer(gtp->sock, NULL);

	synchronize_net();
	udp_tunnel_sock_release(socket);
        return 0;
}

static netdev_tx_t gtp_dev_xmit(struct sk_buff *skb, struct net_device *dev)
{
#ifdef USE_UPSTREAM_TUNNEL
    return rpl_gtp_xmit(skb);
#else
    /* Drop All packets coming from networking stack. OVS-CB is
     * not initialized for these packets.
     */

    dev_kfree_skb(skb);
    dev->stats.tx_dropped++;
    return NETDEV_TX_OK;
#endif
}

static int gtp_change_mtu(struct net_device *dev, int new_mtu)
{
	if (new_mtu < 68 || new_mtu > GTP_MAX_MTU)
		return -EINVAL;

	dev->mtu = new_mtu;
	return 0;
}

static int egress_ipv4_tun_info(struct net_device *dev, struct sk_buff *skb,
				struct ip_tunnel_info *info,
				__be16 sport, __be16 dport)
{
	struct rtable *rt;
	struct flowi4 fl4;

	rt = gtp_get_rt(skb, dev, &fl4, &info->key);
	if (IS_ERR(rt))
		return PTR_ERR(rt);
	ip_rt_put(rt);

	info->key.u.ipv4.src = fl4.saddr;
	info->key.tp_src = sport;
	info->key.tp_dst = dport;
	return 0;
}

int ovs_gtp_fill_metadata_dst(struct net_device *dev, struct sk_buff *skb)
{
	struct gtp_dev *gtp = netdev_priv(dev);
	struct net *net = gtp->net;
	struct ip_tunnel_info *info = skb_tunnel_info(skb);
	__be16 sport, dport;

	sport = htons(get_src_port(net, skb));
	dport = gtp->dst_port;

	if (ip_tunnel_info_af(info) == AF_INET)
		return egress_ipv4_tun_info(dev, skb, info, sport, dport);
	return -EINVAL;
}
EXPORT_SYMBOL_GPL(ovs_gtp_fill_metadata_dst);

static const struct net_device_ops gtp_netdev_ops = {
    .ndo_init               = gtp_init,
    .ndo_uninit             = gtp_uninit,
    .ndo_get_stats64        = ip_tunnel_get_stats64,
    .ndo_open               = gtp_open,
    .ndo_stop               = gtp_stop,
    .ndo_start_xmit         = gtp_dev_xmit,
    .ndo_change_mtu         = gtp_change_mtu,
    .ndo_validate_addr      = eth_validate_addr,
    .ndo_set_mac_address    = eth_mac_addr,
#ifdef USE_UPSTREAM_TUNNEL
#ifdef HAVE_NDO_FILL_METADATA_DST
	.ndo_fill_metadata_dst = gtp_fill_metadata_dst,
#endif
#endif
};

static void gtp_get_drvinfo(struct net_device *dev,
                            struct ethtool_drvinfo *drvinfo)
{
    strlcpy(drvinfo->version, GTP_NETDEV_VER, sizeof(drvinfo->version));
    strlcpy(drvinfo->driver, "gtp", sizeof(drvinfo->driver));
}

static const struct ethtool_ops gtp_ethtool_ops = {
    .get_drvinfo    = gtp_get_drvinfo,
    .get_link       = ethtool_op_get_link,
};

/* Info for udev, that this is a virtual tunnel endpoint */
static struct device_type gtp_type = {
    .name = "gtp",
};

/* Initialize the device structure. */
static void gtp_setup(struct net_device *dev)
{
    ether_setup(dev);

    dev->netdev_ops = &gtp_netdev_ops;
    dev->ethtool_ops = &gtp_ethtool_ops;
    dev->destructor = free_netdev;

    SET_NETDEV_DEVTYPE(dev, &gtp_type);

    dev->features    |= NETIF_F_LLTX | NETIF_F_NETNS_LOCAL;
    dev->features    |= NETIF_F_SG | NETIF_F_HW_CSUM;
    dev->features    |= NETIF_F_RXCSUM;
    dev->features    |= NETIF_F_GSO_SOFTWARE;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,39)
    dev->hw_features |= NETIF_F_SG | NETIF_F_HW_CSUM | NETIF_F_RXCSUM;
    dev->hw_features |= NETIF_F_GSO_SOFTWARE;
#endif
#ifdef USE_UPSTREAM_TUNNEL
    netif_keep_dst(dev);
#endif
    dev->priv_flags |= IFF_LIVE_ADDR_CHANGE | IFF_NO_QUEUE;
	eth_hw_addr_random(dev);
}

static const struct nla_policy gtp_policy[IFLA_GTP_MAX + 1] = {
    [IFLA_GTP_PORT] = { .type = NLA_U16 },
};

static int gtp_validate(struct nlattr *tb[], struct nlattr *data[])
{
    if (tb[IFLA_ADDRESS]) {
        if (nla_len(tb[IFLA_ADDRESS]) != ETH_ALEN)
            return -EINVAL;

        if (!is_valid_ether_addr(nla_data(tb[IFLA_ADDRESS])))
            return -EADDRNOTAVAIL;
    }

    return 0;
}

static struct gtp_dev *find_dev(struct net *net, __be16 dst_port)
{
    struct gtp_net *ln = net_generic(net, gtp_net_id);
    struct gtp_dev *dev;

    list_for_each_entry(dev, &ln->gtp_list, next) {
        if (dev->dst_port == dst_port)
            return dev;
    }
    return NULL;
}

static int gtp_configure(struct net *net, struct net_device *dev,
			  __be16 dst_port)
{
    struct gtp_net *ln = net_generic(net, gtp_net_id);
    struct gtp_dev *gtp = netdev_priv(dev);
    int err;

    gtp->net = net;
    gtp->dev = dev;

    gtp->dst_port = dst_port;

    if (find_dev(net, dst_port))
        return -EBUSY;
	
    err = gtp_change_mtu(dev, GTP_MAX_MTU);
	if (err)
               return err;	

    err = register_netdevice(dev);
    if (err)
        return err;

    list_add(&gtp->next, &ln->gtp_list);
    return 0;
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,39)
static int gtp_newlink(struct net *net, struct net_device *dev,
                       struct nlattr *tb[], struct nlattr *data[])
{
#else
static int gtp_newlink(struct net_device *dev,
                       struct nlattr *tb[], struct nlattr *data[])

{
    struct net *net = &init_net;
#endif
    __be16 dst_port = htons(GTP_UDP_PORT);

    if (data[IFLA_GTP_PORT])
        dst_port = nla_get_be16(data[IFLA_GTP_PORT]);

    return gtp_configure(net, dev, dst_port);
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,39)
static void gtp_dellink(struct net_device *dev, struct list_head *head)
#else
static void gtp_dellink(struct net_device *dev)
#endif
{
    struct gtp_dev *gtp = netdev_priv(dev);

    list_del(&gtp->next);
    unregister_netdevice_queue(dev, head);
}

static size_t gtp_get_size(const struct net_device *dev)
{
    return nla_total_size(sizeof(__be32));  /* IFLA_GTP_PORT */
}

static int gtp_fill_info(struct sk_buff *skb, const struct net_device *dev)
{
    struct gtp_dev *gtp = netdev_priv(dev);

    if (nla_put_be16(skb, IFLA_GTP_PORT, gtp->dst_port))
        goto nla_put_failure;

    return 0;

nla_put_failure:
    return -EMSGSIZE;
}

static struct rtnl_link_ops gtp_link_ops __read_mostly = {
    .kind           = "gtp",
    .maxtype        = IFLA_GTP_MAX,
    .policy         = gtp_policy,
    .priv_size      = sizeof(struct gtp_dev),
    .setup          = gtp_setup,
    .validate       = gtp_validate,
    .newlink        = gtp_newlink,
    .dellink        = gtp_dellink,
    .get_size       = gtp_get_size,
    .fill_info      = gtp_fill_info,
};

struct net_device *rpl_gtp_dev_create_fb(struct net *net, const char *name,
                                         u8 name_assign_type, u16 dst_port)
{
    struct nlattr *tb[IFLA_MAX + 1];
    struct net_device *dev;
    int err;

    memset(tb, 0, sizeof(tb));
    dev = rtnl_create_link(net, (char *) name, name_assign_type,
                           &gtp_link_ops, tb);
    if (IS_ERR(dev))
        return dev;

    err = gtp_configure(net, dev, htons(dst_port));
    if (err) {
        free_netdev(dev);
        return ERR_PTR(err);
    }
    return dev;
}
EXPORT_SYMBOL_GPL(rpl_gtp_dev_create_fb);

static int gtp_init_net(struct net *net)
{
    struct gtp_net *ln = net_generic(net, gtp_net_id);

    INIT_LIST_HEAD(&ln->gtp_list);
    return 0;
}

static void gtp_exit_net(struct net *net)
{
    struct gtp_net *ln = net_generic(net, gtp_net_id);
    struct gtp_dev *gtp, *next;
    struct net_device *dev, *aux;
    LIST_HEAD(list);

    rtnl_lock();

    /* gather any gtp devices that were moved into this ns */
    for_each_netdev_safe(net, dev, aux)
    if (dev->rtnl_link_ops == &gtp_link_ops)
        unregister_netdevice_queue(dev, &list);

    list_for_each_entry_safe(gtp, next, &ln->gtp_list, next) {
        /* If gtp->dev is in the same netns, it was already added
         * to the gtp by the previous loop.
         */
        if (!net_eq(dev_net(gtp->dev), net))
            unregister_netdevice_queue(gtp->dev, &list);
    }

    /* unregister the devices gathered above */
    unregister_netdevice_many(&list);
    rtnl_unlock();
}

static struct pernet_operations gtp_net_ops = {
    .init = gtp_init_net,
    .exit = gtp_exit_net,
    .id   = &gtp_net_id,
    .size = sizeof(struct gtp_net),
};


int rpl_gtp_init_module(void)
{
    int rc;

    rc = register_pernet_subsys(&gtp_net_ops);
    if (rc)
        goto out1;

    rc = rtnl_link_register(&gtp_link_ops);
    if (rc)
        goto out2;

    pr_info("GTP tunneling driver\n");
    return 0;
out2:
    unregister_pernet_subsys(&gtp_net_ops);
out1:
    pr_err("Error while initializing LISP %d\n", rc);	
    return rc;
}

void rpl_gtp_cleanup_module(void)
{
    rtnl_link_unregister(&gtp_link_ops);
    unregister_pernet_subsys(&gtp_net_ops);
}	
