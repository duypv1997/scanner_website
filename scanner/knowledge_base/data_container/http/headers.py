from scanner.knowledge_base.data_container.dc import DataContainer


class HTTPHeaders(DataContainer):
	def __init__(self, data, normalize=True):
		self.auto_normalize = normalize
		self._header_list = data or []

	def _build_str(self):
		return "\n".join("{}: {}".format(k, v) for k, v in self._header_list)

	def to_dict(self):
		return { k: v for k, v in self._header_list }

