#!/usr/bin/python

import socket


UDP_IP = "10.0.5.2"
UDP_PORT = 2152
MESSAGE = '30ff00540000000145000054f1fd40004001c62fc0bc0102c0bc00010800aa403aaf00012131765800000000b0b20c0000000000101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f3031323334353637'.decode('hex')

print "UDP target IP:", UDP_IP
print "UDP target port:", UDP_PORT
print "message:", MESSAGE

sock = socket.socket(socket.AF_INET, # Internet
                     socket.SOCK_DGRAM) # UDP
sock.bind(("0.0.0.0", 2152))

sock.sendto(MESSAGE, (UDP_IP, UDP_PORT))


