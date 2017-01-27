#!/bin/bash

ID=$1

ovs-ofctl del-flows ovs-br 'in_port=4,ip,udp,tp_dst=2152,nw_dst=10.0.5.102'
ovs-ofctl del-flows ovs-br "tun_src=10.0.5.1,tun_id=$ID"

ovs-ofctl del-flows ovs-br "in_port=1,dl_type=0x0800,vlan_tci=0,ip,nw_dst=192.188.0.0/16,nw_src=10.0.5.201"
ovs-ofctl del-flows ovs-br "in_port=1,dl_type=0x0800,vlan_tci=0,ip,nw_dst=192.188.0.0/16,nw_src=192.188.0.0/16"


