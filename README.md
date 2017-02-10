# FLEX
FIRE LTE testbeds for open experimentation

In ovs, we gather an OpenvSwitch GTP patch that allows us to manage GTP 
tunnels https://patchwork.ozlabs.org/patch/579431/. It was written by 
Niti Rohilla and Saloni Jain from TATA Consultancy Services (TCS). The 
patch resembles the work on GRE/VXLAN tunnels already implemented in the 
Linux kernel. The patch is compatible with OVS version 2.5.1, but can be 
also downloaded as part of OVS 2.6.1 from the git repository of Ashish 
Kurian https://github.com/ashishkurian/ovs. To build the OVS with the 
GTP support one has to follow the procedure:

git clone https://github.com/ashishkurian/ovs.git
export DEB_BUILD_OPTIONS=nocheck
cd ovs
dpkg-buildpackage -b -us -uc
cd ..
dpkg -i openvswitch-common_2.6.90-1_amd64.deb \
openvswitch-switch_2.6.90-1_amd64.deb

We also included a patch for a usespace marching of gtp_teid.
The datapath modification of the gtp_teid is still on-going.

ovs-ofctl -O OpenFlow14 add-flow ovs-br \
'in_port=X,ip,udp,tp_src=2152,tp_dst=2152,gtp_teid=0x1,action=NORMAL'

ovs-ofctl -O OpenFlow14 dump-flows ovs-br

tracker.py is a script that observes both the control plane and the 
data plane between the EPC and ENB, to gather the parameters required
by caching.
