from scanner.core.controller.plugin import DetectorPlugin
from scanner.knowledge_base.data_container.domain import Domain
from scanner.misc.utils.logger import singleton_logger as core_logger
from flextls.exception import NotEnoughData, WrongProtocolVersion

import socket, flextls
from flextls.connection import SSLv30Connection
from flextls.protocol.handshake import ClientHello, Handshake, ServerHello
from flextls.field import CipherSuiteField, CompressionMethodField
from flextls.field import ServerNameField, HostNameField


class poodle(DetectorPlugin):
	"""
	Detect POODLE attack
	"""
	NAME = "POODLE"
	RESOURCE_TYPES = [ Domain ]
	CS_VULN_TEMPLATE_ID = "2000021"

	@staticmethod
	def _build_handshake_msg(protocol_version):
		hello = ClientHello()
		ver_major, ver_minor = flextls.helper.get_tls_version(protocol_version)
		hello.version.major = ver_major
		hello.version.minor = ver_minor
		comp_methods = flextls.registry.tls.compression_methods.get_ids()
		cipher_suites = flextls.registry.tls.cipher_suites.get_ids()

		for cipher_id in cipher_suites:
			cipher = CipherSuiteField()
			cipher.value = cipher_id
			hello.cipher_suites.append(cipher)

		for comp_id in comp_methods:
			comp = CompressionMethodField()
			comp.value = comp_id
			hello.compression_methods.append(comp)

		msg_handshake = Handshake()
		msg_handshake.set_payload(hello)
		return msg_handshake


	def _handshake(self, host, port, protocol_version):
		s = socket.socket()
		s.connect((host, port))
		conn = SSLv30Connection(protocol_version=protocol_version)
		hello_msg = self._build_handshake_msg(protocol_version)
		for m in conn.encode(hello_msg):
			s.send(m)

		while True:
			try:
				data = s.recv(4096)
			except socker.error as e:
				break
			
			if not data:
				break

			try:
				conn.decode(data)
			except WrongProtocolVersion as e:
				break
				
			while not conn.is_empty():
				record = conn.pop_record()
				if isinstance(record, Handshake):
					if isinstance(record.payload, ServerHello):
						return True
			# break
		return False

	def detect(self, domain):
		if self._handshake(host=domain.host, port=domain.port, protocol_version=flextls.registry.version.SSLv3):
			attributes = {
				"host": domain.host,
				"port": domain.port
			}
			core_logger.info("Vulnerability is found: %s, host=%s, port=%s"%(self.get_name(), domain.host, domain.port))
			self.save_vuln(attributes=attributes)
