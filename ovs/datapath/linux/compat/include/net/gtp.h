#ifndef __NET_GTP_WRAPPER_H
#define __NET_GTP_WRAPPER_H  1

#ifdef CONFIG_INET
#include <net/udp_tunnel.h>
#endif


#ifdef CONFIG_INET
#define gtp_dev_create_fb rpl_gtp_dev_create_fb
struct net_device *rpl_gtp_dev_create_fb(struct net *net, const char *name,
                                         u8 name_assign_type, u16 dst_port);
#endif /*ifdef CONFIG_INET */

#define gtp_init_module rpl_gtp_init_module
int rpl_gtp_init_module(void);

#define gtp_cleanup_module rpl_gtp_cleanup_module
void rpl_gtp_cleanup_module(void);

#define gtp_xmit rpl_gtp_xmit
netdev_tx_t rpl_gtp_xmit(struct sk_buff *skb);

#define gtp_fill_metadata_dst ovs_gtp_fill_metadata_dst
int ovs_gtp_fill_metadata_dst(struct net_device *dev, struct sk_buff *skb);

#endif /*ifdef__NET_GTP_H */
