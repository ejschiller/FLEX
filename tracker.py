'''
Packet sniffer in python using the pcapy python library
 
Project website
http://oss.coresecurity.com/projects/pcapy.html
'''
 
import socket
from struct import *
import datetime
import pcapy
import sys
from libmich.asn1.processor import *
from types import *


# generate_modules({'S1AP':'S1AP_36413-c10'})
load_module('S1AP')

db = {}
inner = {}

ASN1.ASN1Obj.CODEC = PER
PER.VARIANT = 'A'
pdu = GLOBAL.TYPE['S1AP-PDU']

def decode_string(buf):
    error = 0
    try:
        error = 0
        pdu.decode(buf);
        val = pdu()
    except:
        error = 1;

    return error

def get_val_from_tuple(text, tup):
    index = 0

    if not isinstance(tup, tuple):
        return 1, ""

    try:
        index = tup.index(text);
    
    except:
        return 1, ""

    if index + 1 >= len(tup):
        return 1, ""

    else:
        return 0, index+1


def get_enb_gtp_teid():
    error = 0
    index = 0
    
    pdu_val = pdu()

    error, index = get_val_from_tuple('initiatingMessage', pdu_val)

    if error:
        return

    inm = pdu_val[index]

    if not isinstance (inm, dict):
        return 

    if not 'value' in inm:
        return 
   
    error, index = get_val_from_tuple('InitialContextSetupRequest', inm['value']) 

    if error:
        return 

    icsr = inm['value'][index]

    if not isinstance(icsr, dict):
        return 

    if not 'protocolIEs' in icsr:
        return 

    for item in icsr['protocolIEs']:
        if not isinstance(item, dict):
            continue
        else:
            if 'value' in item:
                err1, ind1 = get_val_from_tuple('E-RABToBeSetupListCtxtSUReq', item['value'])
                if err1:
                    continue
                else:
                    x = item['value'][ind1]
                    for y in x:
                        if isinstance(y, dict):
                            if 'value' in y:
                                z = y['value']
                                err2, ind2 = get_val_from_tuple('E-RABToBeSetupItemCtxtSUReq', z)

                                if err2:
                                    continue
                                else:
                                    if isinstance(z[ind2], dict):
                                        if 'e-RAB-ID' in z[ind2] and 'gTP-TEID' in z[ind2]:
                                            if isinstance(z[ind2]['e-RAB-ID'], int) and isinstance(z[ind2]['gTP-TEID'], str):
                                                if not z[ind2]['e-RAB-ID'] in db:
                                                    db[z[ind2]['e-RAB-ID']] = {}

                                                db[z[ind2]['e-RAB-ID']]['ENB-TEID'] = z[ind2]['gTP-TEID'].encode('hex')
						print '****'
                                                print db
						print '****'
 
def get_mme_gtp_teid():
    error = 0
    index = 0

    pdu_val = pdu()
    error, index = get_val_from_tuple('successfulOutcome', pdu_val)

    if error:
        return

    inm = pdu_val[index]

    if not isinstance (inm, dict):
        return 

    if not 'value' in inm:
        return 
   
    error, index = get_val_from_tuple('InitialContextSetupResponse', inm['value']) 

    if error:
        return 

    icsr = inm['value'][index]

    if not isinstance(icsr, dict):
        return 

    if not 'protocolIEs' in icsr:
        return 

    for item in icsr['protocolIEs']:
        if not isinstance(item, dict):
            continue
        else:
            if 'value' in item:
                err1, ind1 = get_val_from_tuple('E-RABSetupListCtxtSURes', item['value'])
                if err1:
                    continue
                else:
                    x = item['value'][ind1]
                    for y in x:
                        if isinstance(y, dict):
                            if 'value' in y:
                                z = y['value']
                                err2, ind2 = get_val_from_tuple('E-RABSetupItemCtxtSURes', z)

                                if err2:
                                    continue
                                else:
                                    if isinstance(z[ind2], dict):
                                        if 'e-RAB-ID' in z[ind2] and 'gTP-TEID' in z[ind2]:
                                            if isinstance(z[ind2]['e-RAB-ID'], int) and isinstance(z[ind2]['gTP-TEID'], str):
                                                if not z[ind2]['e-RAB-ID'] in db:
                                                    db[z[ind2]['e-RAB-ID']] = {}

                                                db[z[ind2]['e-RAB-ID']]['MME-TEID'] = z[ind2]['gTP-TEID'].encode('hex')
						print '****'
                                                print db
						print '****'
 
#function to parse a packet
def parse_packet(packet) :

    #parse ethernet header
    eth_length = 14
     
    eth_header = packet[:eth_length]
    eth = unpack('!6s6sH' , eth_header)
    eth_protocol = socket.ntohs(eth[2])
    # print 'Destination MAC : ' + eth_addr(packet[0:6]) + ' Source MAC : ' + eth_addr(packet[6:12]) + ' Protocol : ' + str(eth_protocol)
 
    #Parse IP packets, IP Protocol number = 8
    if eth_protocol == 8 :
        #Parse IP header
        #take first 20 characters for the ip header
        ip_header = packet[eth_length:20+eth_length]
         
        #now unpack them :)
        iph = unpack('!BBHHHBBH4s4s' , ip_header)
 
        version_ihl = iph[0]
        version = version_ihl >> 4
        ihl = version_ihl & 0xF
 
        iph_length = ihl * 4
 
        ttl = iph[5]
        protocol = iph[6]
        s_addr = socket.inet_ntoa(iph[8]);
        d_addr = socket.inet_ntoa(iph[9]);
 
        # print 'Version : ' + str(version) + ' IP Header Length : ' + str(ihl) + ' TTL : ' + str(ttl) + ' Protocol : ' + str(protocol) + ' Source Address : ' + str(s_addr) + ' Destination Address : ' + str(d_addr)
 
        #UDP packets
        if protocol == 17 :
            u = iph_length + eth_length
            udph_length = 8
            udp_header = packet[u:u+8]
 
            #now unpack them :)
            udph = unpack('!HHHH' , udp_header)
             
            source_port = udph[0]
            dest_port = udph[1]
            length = udph[2]
            checksum = udph[3]
             
            # print 'Source Port : ' + str(source_port) + ' Dest Port : ' + str(dest_port) + ' Length : ' + str(length) + ' Checksum : ' + str(checksum)
             
            h_size = eth_length + iph_length + udph_length
            data_size = len(packet) - h_size
             
            #get data from the packet
            # 2152 GPRS

            if data_size > 8 and source_port == 2152 and dest_port == 2152:
                gprs_header = packet[h_size:h_size+8]
                gprsh = unpack('!BBH4s', gprs_header)

                gprs_flags = gprsh[0]
                gprs_type = gprsh[1]
                gprs_size = gprsh[2]
                gprs_teid = gprsh[3]

                # T-PDU = 0xff
                if gprs_type == 0xff:
                    # print "GPRS size: " + str(gprs_size)

                    data_size = len(packet) - h_size - 8

                    data = packet[h_size + 8:]

                    if len(data) > 20:
                        inner_ip_header = data[0:20]
         
                        inner_iph = unpack('!BBHHHBBH4s4s' , inner_ip_header)
 
                        inner_version_ihl = inner_iph[0]
                        inner_version = inner_version_ihl >> 4
                        inner_ihl = inner_version_ihl & 0xF
 
                        inner_iph_length = inner_ihl * 4
 
                        inner_ttl = inner_iph[5]
                        inner_protocol = inner_iph[6]
                        inner_s_addr = socket.inet_ntoa(inner_iph[8]);
                        inner_d_addr = socket.inet_ntoa(inner_iph[9]);
 
                        # print 'Inner source IP addr: ' + str(inner_s_addr) + ' Innder dest IP addr: ' + str (inner_d_addr) + 'Source IP addr: ' + str(s_addr) + ' Dest IP addr: ' + str (d_addr) + ' TEID: ' + gprs_teid.encode('hex')

                        index = gprs_teid.encode('hex')

                        if not index in inner:
                            inner[index] = {}

                        inner[index]['inner_s_addr'] = inner_s_addr
                        inner[index]['inner_d_addr'] = inner_d_addr
                        inner[index]['s_addr'] = s_addr
                        inner[index]['d_addr'] = d_addr

			print '****'
			print db
			print inner
			print '****'



             
            # print 'Data : ' + data
 
        elif protocol == 132 :
            # print 'received sctp packet'
            u = iph_length + eth_length
            sctp_length = 12

            sctp_header = packet[u:u+12]
            sctph = unpack('!HH4s4s', sctp_header)

            source_port = sctph[0]
            dest_port = sctph[1]
            verification_tag = sctph[2].encode('hex')
            checksum = sctph[3].encode('hex')

            # print 'Source port: ' + str(source_port) + ' Destinarion port: ' + str(dest_port) + ' Verification Tag: ' + '0x' + verification_tag + ' Checksum: ' + '0x' + checksum

            u += sctp_length

            while len(packet) - u >= 4:
                chunk_header = packet[u:u+4]

                chknh = unpack('!BBH', chunk_header)

                chunk_type = chknh[0]
                chunk_flags = chknh[1]
                chunk_length = chknh[2]

                chunk_pad = 0

                if chunk_length % 4:
                    chunk_pad = 4 - chunk_length % 4

                #print 'Chunk type: ' + str(hex(chunk_type)) + ' Chunk flags: ' + str(hex(chunk_flags)) + ' Chunk size: ' + str(chunk_length)

                # DATA = 0, data hader should be inside, chunk should fit a packet
                if chunk_type == 0 and u + 12 <= len(packet) and u + chunk_length <= len(packet):
                    chunk_data = packet[u+4:u+4+12]
                    chdth = unpack('!IHHI', chunk_data)

                    chunk_data_transmission_sequence_number = chdth[0]
                    chunk_data_stream_identifier = chdth[1]
                    chunk_data_stream_sequence_number = chdth[2]
                    chunk_data_payload_protocol_identifier = chdth[3]

                    #print 'Transmission Sequence Number' + str(chunk_data_transmission_sequence_number) + ' Stream Identifier: ' + str(chunk_data_stream_identifier) + 'Stream Sequence Number: ' + str(chunk_data_stream_sequence_number) + ' Payload Protocol Identifier: ' + str(chunk_data_payload_protocol_identifier)

                    if chunk_data_payload_protocol_identifier == 18:
                        buf=packet[u+4+12:u+chunk_length]
                        error = decode_string(buf)
                        if not error:
                            get_mme_gtp_teid()
                            get_enb_gtp_teid()

                u += chunk_length + chunk_pad

        #some other IP packet like IGMP

def main(argv):
    #list all devices
    devices = pcapy.findalldevs()
    print devices
     
    #ask user to enter device name to sniff
    print "Available devices are :"
    for d in devices :
        print d
     
    #dev = raw_input("Enter device name to sniff : ")
     
    #print "Sniffing device " + dev
     
    '''
    open device
    # Arguments here are:
    #   device
    #   snaplen (maximum number of bytes to capture _per_packet_)
    #   promiscious mode (1 for true)
    #   timeout (in milliseconds)
    '''
    cap = pcapy.open_live('tap2' , 65536 , 1 , 1000)

    #cap = pcapy.open_offline('attachment.pcap')
 
    #start sniffing packets
    while(1) :
        try:
	    (header, packet) = cap.next()

        #if len(packet) == 0:
        #    break

        #print ('%s: captured %d bytes, truncated to %d bytes' %(datetime.datetime.now(), header.getlen(), header.getcaplen()))
            parse_packet(packet)
        except:
            print db
            print inner

    print db
    print inner
 
#Convert a string of 6 characters of ethernet address into a dash separated hex string
def eth_addr (a) :
    b = "%.2x:%.2x:%.2x:%.2x:%.2x:%.2x" % (ord(a[0]) , ord(a[1]) , ord(a[2]), ord(a[3]), ord(a[4]) , ord(a[5]))
    return b
 
if __name__ == "__main__":
  main(sys.argv)
