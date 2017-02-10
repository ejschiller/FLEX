..
      Licensed under the Apache License, Version 2.0 (the "License"); you may
      not use this file except in compliance with the License. You may obtain
      a copy of the License at

          http://www.apache.org/licenses/LICENSE-2.0

      Unless required by applicable law or agreed to in writing, software
      distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
      WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
      License for the specific language governing permissions and limitations
      under the License.

      Convention for heading levels in Open vSwitch documentation:

      =======  Heading 0 (reserved for the title in a document)
      -------  Heading 1
      ~~~~~~~  Heading 2
      +++++++  Heading 3
      '''''''  Heading 4

      Avoid deeper levels because they do not render well.

=================
Description
=================

This fork of the master branch of OVS supports GTP-U tunneling. It takes care only of the mandatory part of the GTP-U tunneling. This tunneling is similar to the other layer 3 tunneling - lisp. Similar to the case with lisp tunneling,  The GTP tunneling code attaches a header with harcoded source and destination MAC address 06:00:00:00:00:00. This address has all bits set to 0, except the locally administered bit, in order to avoid potential collisions with existing allocations. In order for packets to reach their intended destination, the destination MAC address needs to be rewritten.

GTP is a layer 3 tunneling mechanism, meaning that encapsulated packets do not carry Ethernet headers, and ARP requests shouldn't be sent over the tunnel. Because of this, there are some additional steps required for setting up GTP tunnels in Open vSwitch, until support for L3 tunnels will improve. This can be understood from the flow rules given in the following sections.

There is an installation script *install.sh* included in the repository which can automate the installation of OVS on your machine along with the dependencies. Alternatively you can install the dependencies by the following command

``$ apt-get -y install git wget dh-autoreconf libssl-dev libtool libc6-dev``

Before installing OVS ensure that you have python2.7 or any later version installed on your machine (by default python is > 2.7 on Ubuntu 16) and python six module is also installed.If you do not have python six installed, you can install it by the following commands::

	$ wget https://pypi.python.org/packages/b3/b2/238e2590826bfdd113244a40d9d3eb26918bd798fc187e2360a8367068db/six-1.10.0.tar.gz#md5=34eed507548117b2ab523ab14b2f8b55
	$ tar -xvf six-1.10.0.tar.gz
	$ cd six-1.10.0
	$ sudo python setup.py install

After the OVS is installed, you can install mininet by the following command. Installing mininet is optional. In my scenario I am using mininet to simulate a virtual topology and demonstrate GTP-U tunneling.

``$ apt-get install mininet``

After mininet is installed, the following command will add the ovs-testcontoller as the OVSController for mininet

``$ cp ovs/utilities/ovs-testcontroller /usr/bin/ovs-controller``


Setting up the GTP tunneling port on OVS ::
-----------------------------------------

``$ ovs-vsctl add-br br1``

# flow based tunneling port

``$ ovs-vsctl add-port br1 gtp0 -- set interface gtp0 type=gtp options:remote_ip=flow options:key=flow``

or

# port based tunneling port

``$ ovs-vsctl add-port br1 gtp1 -- set interface gtp1 type=gtp options:remote_ip=<IP of the destination> options:key=flow``

Scenario Explanation
--------------------

In the example scenario we have two virtual machines(VM1 & VM2) with mininet installed on both of them. We have
two hosts attached on each of the VMs. VM1 has hosts H1 and H2 and VM2 has hosts H3 and H4. Tunneling is enabled
between H1 and H3 & between H2 and H4.

A mininet topology is also started on each of the VMs using the python script given in the following sections. A *VM#flow.txt* file is also provided which adds the flow rules on each of these VMs. You have to run the corresponding python file to
automatically add the mininet topology and the flows. The script also configures the GTP port on the VMs automatically so that you do not have to explicitly set up GTP ports as explained in the above section. If you look into the files, you can understand the working.

Before adding the topology and GTP port, the VMs should be setup in such a way that you can ping one VM from the other. This you need to setup while configuring your machines. There are youtube videos showing how to connect two VMs and establish ping between them. In this particular scenario VM1 is having an ethernet port eth1 with IP address 192.168.56.101 and VM2 is having an ethernet port eth1 with IP address 192.168.56.103. The VM1 can ping VM2 through the ethernet port eth1 on each of the VMs.


The following python script can be run on VM1 to setup the gtp port and mininet topology::

	from mininet.topo import Topo
	from mininet.net import Mininet
	from mininet.log import setLogLevel, info
	from mininet.node import OVSController, RemoteController,Node
	from mininet.cli import CLI

	class SimplePktSwitch(Topo):
	    """Simple topology example."""

	    def __init__(self, **opts):
		"""Create custom topo."""
		import os
		os.system ('sudo mn -c')
		# Initialize topology
		# It uses the constructor for the Topo cloass
		super(SimplePktSwitch, self).__init__(**opts)

		# Adding hosts and setting IP and MAC addresses
		h1 = self.addHost('h1', ip='10.0.0.1',mac='00:00:00:00:00:01')
		h2 = self.addHost('h2', ip='10.0.0.2',mac='00:00:00:00:00:02')

		# Adding switches
		s1 = self.addSwitch('s1')

		# Add links
		self.addLink(h1, s1)
		self.addLink(h2, s1)

	def run():
	    net = Mininet(topo=SimplePktSwitch(),controller=OVSController)
	    net.start()
	    import os
	    # command to setup tunneling port from terminal.
	    os.system ('sudo ovs-vsctl add-port s1 gtp1 -- set interface gtp1 type=gtp option:remote_ip=192.168.56.103 option:key=flow ofport_request=10')
	    os.system ('sudo ovs-ofctl add-flows s1 VM1flow.txt')
	    # following commands are to connect eth1 to the OVS to enable communication between VMs directly
	    os.system ('sudo ovs-vsctl add-port s1 enp0s8')
	    os.system ('sudo ifconfig enp0s8 0.0.0.0')
	    os.system ('sudo ifconfig s1 192.168.56.101')

	    CLI(net)
	    net.stop()
	# if the script is run directly (sudo custom/optical.py):
	if __name__ == '__main__':
	    setLogLevel('info')
	run()
The content of VM1flow.txt should be as::
 
	table=0,dl_type=0x0800,dl_dst=06:00:00:00:00:00,tun_id=0x1,action=mod_dl_dst:00:00:00:00:00:01,output:1
	table=0,dl_type=0x0800,dl_dst=06:00:00:00:00:00,tun_id=0x2,action=mod_dl_dst:00:00:00:00:00:02,output:2
	table=0,in_port=1,dl_type=0x0800,action=set_field:192.168.56.103->tun_dst,set_field:0x1->tun_id,output:10
	table=0,in_port=2,dl_type=0x0800,action=set_field:192.168.56.103->tun_dst,set_field:0x2->tun_id,output:10
	# Normal action for all other flows. This ensures that arp is not forwarded through the tunnel
	table=0,dl_type=0x0806,action=NORMAL

 
The following python script can be run on VM2 to setup the gtp port and mininet topology::


	from mininet.topo import Topo
	from mininet.net import Mininet
	from mininet.log import setLogLevel, info
	from mininet.node import OVSController, RemoteController,Node
	from mininet.cli import CLI

	class SimplePktSwitch(Topo):
    	    """Simple topology example."""

    	    def __init__(self, **opts):
        	"""Create custom topo."""
		import os
		os.system ('sudo mn -c')
        	# Initialize topology
        	# It uses the constructor for the Topo cloass
        	super(SimplePktSwitch, self).__init__(**opts)

        	# Adding hosts and setting IP and MAC addresses
        	h3 = self.addHost('h3', ip='10.0.0.3',mac='00:00:00:00:00:03')
        	h4 = self.addHost('h4', ip='10.0.0.4',mac='00:00:00:00:00:04')
   	
       		# Adding switches
        	s2 = self.addSwitch('s2')

        	# Add links
        	self.addLink(h3, s2)
        	self.addLink(h4, s2)

	def run():
    	    net = Mininet(topo=SimplePktSwitch(),controller=OVSController)
    	    net.start()
    	    import os
	    # command to setup tunneling port from terminal.
    	    os.system ('sudo ovs-vsctl add-port s2 gtp2 -- set interface gtp2 type=gtp option:remote_ip=192.168.56.101 option:key=flow ofport_request=10')
    	    os.system ('sudo ovs-ofctl add-flows s2 VM2flow.txt')
    	    # following commands are to connect eth1 to the OVS to enable communication between VMs directly
    	    os.system ('sudo ovs-vsctl add-port s2 eth1')
    	    os.system ('sudo ifconfig eth1 0.0.0.0')
    	    os.system ('sudo ifconfig s2 192.168.56.103')
    	    CLI(net)
    	    net.stop()

	# if the script is run directly (sudo custom/optical.py):
	if __name__ == '__main__':
    	setLogLevel('info')
	run()

The content of VM2flow.txt should be as::

	table=0,dl_type=0x0800,dl_dst=06:00:00:00:00:00,tun_id=0x1,action=mod_dl_dst:00:00:00:00:00:03,output:1
	table=0,dl_type=0x0800,dl_dst=06:00:00:00:00:00,tun_id=0x2,action=mod_dl_dst:00:00:00:00:00:04,output:2
	table=0,dl_type=0x0800,in_port=1,dl_type=0x0800,action=set_field:192.168.56.101->tun_dst,set_field:0x1->tun_id,output:10
	table=0,dl_type=0x0800,in_port=2,dl_type=0x0800,action=set_field:192.168.56.101->tun_dst,set_field:0x2->tun_id,output:10
	# Normal action for all other flows. This ensures that arp is not forwarded through the tunnel
	table=0,dl_type=0x0806,action=NORMAL
If everything was configured correctly, you must be able to ping H3 from H1 and vice versa. Also the ping should succeed from H2 to H4 and vice versa. You can change the configurations on the scripts to change the IP, MAC addresses and other parameters.

Eg: H1 ping 10.0.0.3

To setup the networking between the VMs, I used following setup in the interfaces files under /etc/network/interfaces on VM1::

	auto lo enp0s3
	# enp0s3 is the NAT adapter
	iface lo inet loopback
	iface enp0s3 inet dhcp

	auto enp0s8
	# enp0s8 is the internal network adapter
	iface enp0s8 inet static
	address 192.168.56.103
	netmask 255.255.255.0
	gateway 10.0.0.1



