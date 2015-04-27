#!/usr/bin/env python3

import sys
import socket
import struct
import base64
import binascii
 
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

host = "announce.syncthing.net"
port = 22026

MAGIC_QUERY = 0x2CA856F5
MAGIC_ANNOUNCE = 0x9D79BC39

dev_id = sys.argv[1]

# remove block seperators
dev_id = dev_id.replace("-", "")

# strip check digits
dev_id_b = bytearray(dev_id, encoding="ASCII")
for i in range(1, 5):
	del dev_id_b[i*14-i]
dev_id = str(dev_id_b, encoding="ASCII")

dev_id = base64.b32decode(dev_id + "====")

msg = struct.pack("!II32s", MAGIC_QUERY, 32, dev_id)
s.sendto(msg, (host, port))

reply, addr = s.recvfrom(1024)

offset = 0
def unpt(fmt):
	global offset
	r = struct.unpack_from(fmt, reply, offset=offset)
	offset += struct.calcsize(fmt)
	return r

def unp(fmt):
	return unpt(fmt)[0]

def unp_dev():
	assert unp("!I") == 32 # length of device id
	device_id = unp("!32s")
	addresses = []
	# get addresses
	for j in range(0, unp("!I")):
		addr_len = unp("!I")
		if addr_len == 4:
			# ipv4
			address = "%i.%i.%i.%i" % unpt("!BBBB")
		elif addr_len == 16:
			# ipv6
			address = "[%04X:%04X:%04X:%04X:%04X:%04X:%04X:%04X]" % unpt("!HHHHHHHH")
		else:
			raise ValueError("Unexpected ip address length: %i" % addr_len)
		port = str(unp("!I"))
		addresses.append(":".join((address, port)))
	return (device_id, addresses)


assert unp("!I") == MAGIC_ANNOUNCE
devices = [unp_dev()]

# get extra devices
for i in range(0, unp("!I")):
	devices.append(unp_dev())

# filter results (only keep requested dev ids)
devices = filter(lambda d: d[0] == dev_id, devices)

addresses = []

for did, daddrs in devices:
	addresses.extend(daddrs)

for addr in addresses:
	print(addr)
