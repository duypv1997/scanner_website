from scanner.core.controller.plugin import DetectorPlugin
from scanner.knowledge_base.data_container.domain import Domain
from scanner.misc.utils.logger import singleton_logger as core_logger

import math, socket, os, ssl, gmpy2
from cryptography import x509
from cryptography.hazmat.backends import default_backend


class robot_attack(DetectorPlugin):
	"""
	Detect ROBOT attack vulnerabilities
	"""
	NAME = "ROBOT attack"
	CS_VULN_ROBOT_ATTACK = "2000020"
	RESOURCE_TYPES = [ Domain ]

	# This uses all TLS_RSA ciphers with AES and 3DES
	CH_DEF = bytearray.fromhex("16030100610100005d03034f20d66cba6399e552fd735d75feb0eeae2ea2ebb357c9004e21d0c2574f837a000010009d003d0035009c003c002f000a00ff01000024000d0020001e060106020603050105020503040104020403030103020303020102020203")

	# This uses only TLS_RSA_WITH_AES_128_CBC_SHA (0x002f)
	CH_CBC = bytearray.fromhex("1603010055010000510303ecce5dab6f55e5ecf9cccd985583e94df5ed652a07b1f5c7d9ba7310770adbcb000004002f00ff01000024000d0020001e060106020603050105020503040104020403030103020303020102020203")

	# This uses only TLS-RSA-WITH-AES-128-GCM-SHA256 (0x009c)
	CH_GCM = bytearray.fromhex("1603010055010000510303ecce5dab6f55e5ecf9cccd985583e94df5ed652a07b1f5c7d9ba7310770adbcb000004009c00ff01000024000d0020001e060106020603050105020503040104020403030103020303020102020203")

	CSS = bytearray.fromhex("000101")
	ENC = bytearray.fromhex("005091a3b6aaa2b64d126e5583b04c113259c4efa48e40a19b8e5f2542c3b1d30f8d80b7582b72f08b21dfcbff09d4b281676a0fb40d48c20c4f388617ff5c00808a96fbfe9bb6cc631101a6ba6b6bc696f0")

	MSG_FASTOPEN = 0x20000000
	# set to true if you want to generate a signature or if the first ciphertext is not PKCS#1 v1.5 conform
	EXECUTE_BLINDING = True
	TIMEOUT  = 5
	ENABLE_FASTOPEN = os.path.exists("/proc/sys/net/ipv4/tcp_fastopen")


	def detect(self, domain):
		if self.check(domain.host, domain.port):
			attributes = {
				"host": domain.host,
				"port": domain.port
			}
			core_logger.info("Vulnerability is found: %s, host=%s, port=%s"%(self.get_name(), domain.host, domain.port))
			self.save_vuln(attributes=attributes)

	@staticmethod
	def to_bytes(n, length, endianess='big'):
		h = '%x' % n
		s = bytes.fromhex('0'*(len(h) % 2) + h).zfill(length*2)
		return s if endianess == 'big' else s[::-1]

	def get_rsa_from_server(self, server, port):
		try:
			ctx = ssl.create_default_context()
			ctx.check_hostname = False
			ctx.verify_mode = ssl.CERT_NONE
			ctx.set_ciphers("RSA")
			raw_socket = socket.socket()
			raw_socket.settimeout(self.TIMEOUT)
			s = ctx.wrap_socket(raw_socket)
			s.connect((server, port))
			cert_raw = s.getpeercert(binary_form=True)
			cert_dec = x509.load_der_x509_certificate(cert_raw, default_backend())
			return cert_dec.public_key().public_numbers().n, cert_dec.public_key().public_numbers().e
		except ssl.SSLError as e:
			return None
		except (ConnectionRefusedError, socket.timeout) as e:
			return None
		except:
			return None

	def oracle(self, ip, port, cke_2nd_prefix, pms, messageflow=False):
		try:
			s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
			s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
			if not self.ENABLE_FASTOPEN:
				s.connect((ip, port))
				s.sendall(self.CH_CBC)
			else:
				s.sendto(self.CH_CBC, self.MSG_FASTOPEN, (ip, port))
			s.settimeout(self.TIMEOUT)
			buf = bytearray.fromhex("")
			i = 0
			bend = 0
			while True:
				# we try to read twice
				while i + 5 > bend:
					buf += s.recv(4096)
					bend = len(buf)
				# this is the record size
				psize = buf[i + 3] * 256 + buf[i + 4]
				# if the size is 2, we received an alert
				if (psize == 2):
					return ("The server sends an Alert after ClientHello")
				# try to read further record data
				while i + psize + 5 > bend:
					buf += s.recv(4096)
					bend = len(buf)
				# check whether we have already received a ClientHelloDone
				if (buf[i + 5] == 0x0e) or (buf[bend - 4] == 0x0e):
					break
				i += psize + 5
			self.cke_version = buf[9:11]
			s.send(bytearray(b'\x16') + self.cke_version)
			s.send(cke_2nd_prefix)
			s.send(pms)
			if not messageflow:
				s.send(bytearray(b'\x14') + self.cke_version + self.CSS)
				s.send(bytearray(b'\x16') + self.cke_version + self.ENC)
			try:
				alert = s.recv(4096)
				if len(alert) == 0:
					return ("No data received from server")
				if alert[0] == 0x15:
					if len(alert) < 7:
						return ("TLS alert was truncated (%s)" % (repr(alert)))
					return ("TLS alert %i of length %i" % (alert[6], len(alert)))
				else:
					return "Received something other than an alert (%s)" % (alert[0:10])
			except ConnectionResetError as e:
				return "ConnectionResetError"
			except socket.timeout:
				return ("Timeout waiting for alert")
			s.close()
		except Exception as e:
			return str(e)

	def check(self, host, port):
		ip = socket.gethostbyname(host)
		res = self.get_rsa_from_server(ip, port)
		if res is None:
			return False
	
		N, e = res 
		modulus_bits = int(math.ceil(math.log(N, 2)))
		modulus_bytes = (modulus_bits + 7) // 8

		cke_2nd_prefix = bytearray.fromhex("{0:0{1}x}".format(modulus_bytes + 6, 4) + "10" + "{0:0{1}x}".format(modulus_bytes + 2, 6) + "{0:0{1}x}".format(modulus_bytes, 4))
		# pad_len is length in hex chars, so bytelen * 2
		pad_len = (modulus_bytes - 48 - 3) * 2
		rnd_pad = ("abcd" * (pad_len // 2 + 1))[:pad_len]
		rnd_pms = "aa112233445566778899112233445566778899112233445566778899112233445566778899112233445566778899"
		pms_good_in = int("0002" + rnd_pad + "00" + "0303" + rnd_pms, 16)
		# wrong first two bytes
		pms_bad_in1 = int("4117" + rnd_pad + "00" + "0303" + rnd_pms, 16)
		# 0x00 on a wrong position, also trigger older JSSE bug
		pms_bad_in2 = int("0002" + rnd_pad + "11" + rnd_pms + "0011", 16)
		# no 0x00 in the middle
		pms_bad_in3 = int("0002" + rnd_pad + "11" + "1111" + rnd_pms, 16)
		# wrong version number (according to Klima / Pokorny / Rosa paper)
		pms_bad_in4 = int("0002" + rnd_pad + "00" + "0202" + rnd_pms, 16)
	
		pms_good = self.to_bytes(int(gmpy2.powmod(pms_good_in, e, N)), modulus_bytes, endianess="big")
		pms_bad1 = self.to_bytes(int(gmpy2.powmod(pms_bad_in1, e, N)), modulus_bytes, endianess="big")
		pms_bad2 = self.to_bytes(int(gmpy2.powmod(pms_bad_in2, e, N)), modulus_bytes, endianess="big")
		pms_bad3 = self.to_bytes(int(gmpy2.powmod(pms_bad_in3, e, N)), modulus_bytes, endianess="big")
		pms_bad4 = self.to_bytes(int(gmpy2.powmod(pms_bad_in4, e, N)), modulus_bytes, endianess="big")
	
		oracle_good = self.oracle(ip,port,cke_2nd_prefix,pms_good, messageflow=False)
		oracle_bad1 = self.oracle(ip,port,cke_2nd_prefix,pms_bad1, messageflow=False)
		oracle_bad2 = self.oracle(ip,port,cke_2nd_prefix,pms_bad2, messageflow=False)
		oracle_bad3 = self.oracle(ip,port,cke_2nd_prefix,pms_bad3, messageflow=False)
		oracle_bad4 = self.oracle(ip,port,cke_2nd_prefix,pms_bad4, messageflow=False)

		if (oracle_good == oracle_bad1 == oracle_bad2 == oracle_bad3 == oracle_bad4):
			self.flow = False
			oracle_good = self.oracle(ip,port,cke_2nd_prefix,pms_good, messageflow=True)
			oracle_bad1 = self.oracle(ip,port,cke_2nd_prefix,pms_bad1, messageflow=True)
			oracle_bad2 = self.oracle(ip,port,cke_2nd_prefix,pms_bad2, messageflow=True)
			oracle_bad3 = self.oracle(ip,port,cke_2nd_prefix,pms_bad3, messageflow=True)
			oracle_bad4 = self.oracle(ip,port,cke_2nd_prefix,pms_bad4, messageflow=True)
			if (oracle_good == oracle_bad1 == oracle_bad2 == oracle_bad3 == oracle_bad4):
				pass
				# return False
			else:
				self.flow = True
		else:
			self.flow = False
	
		# Re-checking all oracles to avoid unreliable results
		oracle_good_verify = self.oracle(ip,port,cke_2nd_prefix,pms_good, messageflow=self.flow)
		oracle_bad_verify1 = self.oracle(ip,port,cke_2nd_prefix,pms_bad1, messageflow=self.flow)
		oracle_bad_verify2 = self.oracle(ip,port,cke_2nd_prefix,pms_bad2, messageflow=self.flow)
		oracle_bad_verify3 = self.oracle(ip,port,cke_2nd_prefix,pms_bad3, messageflow=self.flow)
		oracle_bad_verify4 = self.oracle(ip,port,cke_2nd_prefix,pms_bad4, messageflow=self.flow)
		
		if (oracle_good != oracle_good_verify) or (oracle_bad1 != oracle_bad_verify1) or (oracle_bad2 != oracle_bad_verify2) or (oracle_bad3 != oracle_bad_verify3) or (oracle_bad4 != oracle_bad_verify4):
			return False
		else:
			if (oracle_bad1 == oracle_bad2 == oracle_bad3):
				oracle_strength = "weak"
				return True
			else:
				oracle_strength = "strong"
			if self.flow:
				flowt = "shortened"
			else:
				flowt = "standard"
	
			if self.cke_version[0] == 3 and self.cke_version[1] == 0:
				self.tlsver = "SSLv3"
			elif self.cke_version[0] == 3 and self.cke_version[1] == 1:
				self.tlsver = "TLSv1.0"
			elif self.cke_version[0] == 3 and self.cke_version[1] == 2:
				self.tlsver = "TLSv1.1"
			elif self.cke_version[0] == 3 and self.cke_version[1] == 3:
				self.tlsver = "TLSv1.2"
			else:
				self.tlsver = "TLS raw version %i/%i" % (self.cke_version[0], self.cke_version[1])
		return False
	