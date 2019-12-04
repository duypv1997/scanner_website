from scanner.knowledge_base.data_container.dc import DataContainer


class Domain(DataContainer):
	"""
	TODO: parse URL
	"""

	def __init__(self, data):
		if not isinstance(data, str):
			raise ValueError("Domain can only be built from string, not %s"%(type(data)))
		self.host, self.port = self._parse(data)

	@staticmethod
	def _parse(data):
		address = data.split(":", 1)
		try:
			host = address[0].strip()
			assert host
		except:
			raise ValueError

		try:
			port = int(address[1])
			assert port > 0 and port < 65535
		except AssertionError:
			raise ValueError
		except IndexError:
			port = None
		return host, port

	def __str__(self):
		s = self.host
		if self.port:
			s = "%s:%s"%(s, self.port)
		return s
