from scanner.core.controller.plugin import DetectorPlugin
from scanner.knowledge_base.data_container.domain import Domain
from scanner.misc.utils.logger import singleton_logger as core_logger

import re, select, time, struct, socket


def h2bin(x):
	return bytes.fromhex(re.sub('\s', '', x))
	# .decode('utf-8')

class heartbleed(DetectorPlugin):
	"""
	Detect Heartbleed vulnerability
	"""
	NAME = "Heartbleed"

	hello = h2bin('''
	16 03 02 00  dc 01 00 00 d8 03 02 53
	43 5b 90 9d 9b 72 0b bc  0c bc 2b 92 a8 48 97 cf
	bd 39 04 cc 16 0a 85 03  90 9f 77 04 33 d4 de 00
	00 66 c0 14 c0 0a c0 22  c0 21 00 39 00 38 00 88
	00 87 c0 0f c0 05 00 35  00 84 c0 12 c0 08 c0 1c
	c0 1b 00 16 00 13 c0 0d  c0 03 00 0a c0 13 c0 09
	c0 1f c0 1e 00 33 00 32  00 9a 00 99 00 45 00 44
	c0 0e c0 04 00 2f 00 96  00 41 c0 11 c0 07 c0 0c
	c0 02 00 05 00 04 00 15  00 12 00 09 00 14 00 11
	00 08 00 06 00 03 00 ff  01 00 00 49 00 0b 00 04
	03 00 01 02 00 0a 00 34  00 32 00 0e 00 0d 00 19
	00 0b 00 0c 00 18 00 09  00 0a 00 16 00 17 00 08
	00 06 00 07 00 14 00 15  00 04 00 05 00 12 00 13
	00 01 00 02 00 03 00 0f  00 10 00 11 00 23 00 00
	00 0f 00 01 01
	''')

	hbv10 = h2bin('''
	18 03 01 00 03
	01 40 00
	''')
	
	hbv11 = h2bin('''
	18 03 02 00 03
	01 40 00
	''')
	
	hbv12 = h2bin('''
	18 03 03 00 03
	01 40 00
	''')

	RESOURCE_TYPES = [ Domain ]
	CS_VULN_TEMPLATE_ID = "1000029"

	def recvmsg(self, s):
		hdr = self.recvall(s, 5)
		if hdr is None:
			return None, None, None
		typ, ver, ln = struct.unpack('>BHH', hdr)
		pay = self.recvall(s, ln, 10)
		if pay is None:
			return None, None, None
		return typ, ver, pay

	def hit_hb(self, s, host):
		while True:
			typ, ver, pay = self.recvmsg(s)
			if typ is None:
				return False

			if typ == 24:
				return True

			if typ == 21:
				return False

	def tls(self, s):
		s.send(self.hello)

	def parse_resp(self, s):
		while True:
			typ, ver, pay = self.recvmsg(s)
			if typ == None:
				return 0
	
			#look for server hello done message
			if typ == 22 and pay[0] == 0x0E:
				return ver

	@staticmethod
	def recvall(s, length, timeout=5):
		endtime = time.time() + timeout
		rdata = bytes()
		remain = length
		while remain > 0:
			rtime = endtime - time.time()
			if rtime < 0:
				if not rdata:
					return None
				else:
					return rdata
			r, w, e = select.select([s], [], [], 5)
			if s in r:
				data = s.recv(remain)
				# EOF?
				if not data:
					return None
				rdata += data
				remain -= len(data)
		return rdata

	@staticmethod
	def connect(host, port):
		s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		s.connect((host, port))
		return s

	def check(self, host, port):
		s = self.connect(host, port)
		self.tls(s)
		version = self.parse_resp(s)
	
		if version == 0:
			return False
		else:
			version = version - 0x0300
	
		if version == 1:
			s.send(self.hbv10)
			response = self.hit_hb(s, host)
		if version == 2:
			s.send(self.hbv11)
			response = self.hit_hb(s, host)
		if version == 3:
			s.send(self.hbv12)
			response = self.hit_hb(s, host)
		s.close()
		return response

	def detect(self, domain):
		if self.check(domain.host, domain.port):
			attributes = {
				"host": domain.host,
				"port": domain.port
			}
			core_logger.info("Vulnerability is found: %s, host=%s, port=%s"%(self.get_name(), domain.host, domain.port))
			self.save_vuln(attributes=attributes)

