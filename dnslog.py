#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @Date	: 2014-06-29 03:01:25
# @Author  : Your Name (you@example.org)
# @Link	: http://example.org
# @Version : $Id$

import SocketServer
import struct
import socket as socketlib
import threading
import time
mutex = threading.Lock()
global outWriter
outWriter=None
ret_ip="127.0.0.1"
# DNS Query
class SinDNSQuery:
	def __init__(self, data):
		i = 0
		self.name = ''
		while True:
			d =struct.unpack('b',data[i])[0]
			if d == 0:
				break;
			#fix the bug of get domain name
			'''if d < 32:
				self.name = self.name + '.'
			else:
				self.name = self.name + chr(d)
                        '''
                        self.name = self.name + data[i+1:i+1+d]+'.'
			i = i+1+d
                self.name = self.name[:-1]
		self.querybytes = data[0:i + 1]
		(self.type, self.classify) = struct.unpack('>HH', data[i + 1:i + 5])
		self.len = i + 5
	def getbytes(self):
		return self.querybytes + struct.pack('>HH', self.type, self.classify)

# DNS Answer RRS
# this class is also can be use as Authority RRS or Additional RRS 
class SinDNSAnswer:
	def __init__(self, ip):
		self.name = 49164
		self.type = 1
		self.classify = 1
		self.timetolive = 190
		self.datalength = 4
		self.ip = ip
	def getbytes(self):
		res = struct.pack('>HHHLH', self.name, self.type, self.classify, self.timetolive, self.datalength)
		s = self.ip.split('.')
		res = res + struct.pack('BBBB', int(s[0]), int(s[1]), int(s[2]), int(s[3]))
		return res

# DNS frame
# must initialized by a DNS query frame
class SinDNSFrame:
	def __init__(self, data):
		(self.id, self.flags, self.quests, self.answers, self.author, self.addition) = struct.unpack('>HHHHHH', data[0:12])
		self.query = SinDNSQuery(data[12:])
	def getname(self):
		return self.query.name
	def setip(self, ip):
		self.answer = SinDNSAnswer(ip)
		self.answers = 1
		self.flags = 33152
	def getbytes(self):
		res = struct.pack('>HHHHHH', self.id, self.flags, self.quests, self.answers, self.author, self.addition)
		res = res + self.query.getbytes()
		if self.answers != 0:
			res = res + self.answer.getbytes()
		return res
# A UDPHandler to handle DNS query
class SinDNSUDPHandler(SocketServer.BaseRequestHandler):
	def handle(self):
		data = self.request[0].strip()
		dns = SinDNSFrame(data)
		socket = self.request[1]
                #print dir(socket)
		namemap = SinDNSServer.namemap
		if(dns.query.type==1):
			# If this is query a A record, then response it
			
			name = dns.getname();
	                global mutex
                        try:
                                mutex.acquire()
			        #print name;
                                outWriter.write(time.strftime('%Y-%m-%d %H:%M:%S',time.localtime(time.time()))+'\t'+self.client_address[0]+'\t'+name+'\n')
                                outWriter.flush()
                        finally:
                                mutex.release()
                                
		#Disable the function for resovle the domain name
			'''
			toip = None
			ifrom = "map"
			if namemap.__contains__(name):
				# If have record, response it
				# dns.setip(namemap[name])
				# socket.sendto(dns.getbytes(), self.client_address)
				toip = namemap[name]
			elif namemap.__contains__('*'):
				# Response default address
				# dns.setip(namemap['*'])
				# socket.sendto(dns.getbytes(), self.client_address)
				toip = namemap['*']
			else:
				# ignore it
				# socket.sendto(data, self.client_address)
				# socket.getaddrinfo(name,0)
				try:
					toip = socketlib.getaddrinfo(name,0)[0][4][0]
					ifrom = "sev"
					# namemap[name] = toip
					# print socket.getaddrinfo(name,0)
				except Exception, e:
					print 'get ip fail'
			if toip:
			'''
			dns.setip(ret_ip)
#			print '%s: %s-->%s (%s)'%(self.client_address[0], name, toip, ifrom)
			socket.sendto(dns.getbytes(), self.client_address)
		else:
			# If this is not query a A record, ignore it
			socket.sendto(data, self.client_address)

# DNS Server
# It only support A record query
# user it, U can create a simple DNS server
class SinDNSServer:
	def __init__(self, port=53):
		SinDNSServer.namemap = {}
		self.port = port
	def addname(self, name, ip):
		SinDNSServer.namemap[name] = ip
	def start(self):
		HOST, PORT = "0.0.0.0", self.port
		server = SocketServer.UDPServer((HOST, PORT), SinDNSUDPHandler)
		server.serve_forever()

# Now, test it
if __name__ == "__main__":
        outWriter = open('dnsout.txt','a')
	sev = SinDNSServer()
	#sev.addname('www.aa.com', '192.168.0.1')	# add a A record
	#sev.addname('www.bb.com', '192.168.0.2')	# add a A record
	# sev.addname('*', '0.0.0.0') # default address
	sev.start() # start DNS server

# Now, U can use "nslookup" command to test it
# Such as "nslookup www.aa.com"
