#!/bin/bash

ID1=$1
ID2=$2

ovs-ofctl add-flow ovs-br 'in_port=4,ip,udp,tp_dst=2152,nw_dst=10.0.5.102,action=mod_nw_dst=10.0.5.2,resubmit:4'
ovs-ofctl add-flow ovs-br "tun_src=10.0.5.1,tun_id=$ID1,action=mod_dl_dst:52:54:00:12:34:01,output:1"

ovs-ofctl add-flow ovs-br "in_port=1,dl_type=0x0800,vlan_tci=0,ip,nw_dst=192.188.0.0/16,nw_src=10.0.5.201,action=set_tunnel:$ID2,set_field:10.0.5.1->tun_dst,output:5"
ovs-ofctl add-flow ovs-br "in_port=1,dl_type=0x0800,vlan_tci=0,ip,nw_dst=192.188.0.0/16,nw_src=192.188.0.0/16,action=set_tunnel:$ID2,set_field:10.0.5.1->tun_dst,output:5"

