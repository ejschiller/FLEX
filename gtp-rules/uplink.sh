#!/bin/bash

ID=$1

ovs-ofctl del-flows ovs-br 'in_port=4,ip,nw_dst=10.0.5.102'
ovs-ofctl del-flows ovs-br "tun_src=10.0.5.1,tun_id=$ID"

ovs-ofctl add-flow ovs-br 'in_port=4,ip,nw_dst=10.0.5.102,action=mod_nw_dst=10.0.5.2,resubmit:4'
ovs-ofctl add-flow ovs-br "tun_src=10.0.5.1,tun_id=$ID,action=mod_dl_dst:52:54:00:12:34:01,output:1"



