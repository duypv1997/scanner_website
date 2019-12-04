from scanner.knowledge_base.data_container.dc import DataContainer


class QueryString(DataContainer):
	"""
	TODO: parse query string
	"""

	def __init__(self, data, normalize=True):
		self.auto_normalize = normalize
		self._cache = data

	def _build_str(self):
		return self._cache

	def __build_cache(self):
		return

	def __bool__(self):
		return bool(self._cache)
