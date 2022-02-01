#!/usr/bin/env python

# Usage - timeout 180 python pyshark.py > capture.pcap

import sys,socket,struct,time
sys.stdout.write(struct.pack('!IHHIIII',0xa1b2c3d4,2,4,0,0,65535,1))
s=socket.socket(socket.PF_PACKET, socket.SOCK_RAW, socket.htons(0x3))
while True:
    t,p=time.time(),s.recvfrom(65535)
    ts=int(t)
    tu=int((t-ts)*1000000)
    sys.stdout.write(struct.pack('!IIII',ts,tu,len(p[0]),len(p[0]))+p[0])
