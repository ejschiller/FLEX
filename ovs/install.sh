sudo apt-get -y install git wget dh-autoreconf libssl-dev libtool libc6-dev
sudo ./boot.sh
sudo ./configure --with-linux=/lib/modules/`uname -r`/build
sudo make
sudo make install
sudo cp datapath/linux/openvswitch.ko /lib/modules/`uname -r`/kernel/net/openvswitch/openvswitch.ko
sudo make modules_install
sudo /sbin/modprobe openvswitch
/sbin/lsmod
sudo mkdir -p /usr/local/etc/openvswitch
sudo ovsdb-tool create /usr/local/etc/openvswitch/conf.db vswitchd/vswitch.ovsschema
sudo mkdir -p /usr/local/var/run/openvswitch
sudo ovsdb-server --remote=punix:/usr/local/var/run/openvswitch/db.sock --remote=db:Open_vSwitch,Open_vSwitch,manager_options --private-key=db:Open_vSwitch,SSL,private_key --certificate=db:Open_vSwitch,SSL,certificate --bootstrap-ca-cert=db:Open_vSwitch,SSL,ca_cert --pidfile --detach
sudo ovs-vsctl --no-wait init
sudo ovs-vswitchd --pidfile --detach
#Following is to automate the ovs-db starting on every reboot
#not shown in OVS github
cd ~/
cd /etc/init.d
sudo su <<HERE
echo "#! /bin/sh" >> ovsstart
echo "sudo ovsdb-server --remote=punix:/usr/local/var/run/openvswitch/db.sock --remote=db:Open_vSwitch,Open_vSwitch,manager_options --private-key=db:Open_vSwitch,SSL,private_key --certificate=db:Open_vSwitch,SSL,certificate --bootstrap-ca-cert=db:Open_vSwitch,SSL,ca_cert --pidfile --detach" >> ovsstart
echo "sudo ovs-vsctl --no-wait init" >> ovsstart
echo "sudo ovs-vswitchd --pidfile --detach" >> ovsstart
sudo chmod ugo+x ovsstart
sudo update-rc.d ovsstart defaults
HERE
cd ~/
