from scanner.knowledge_base.data_container.dc import DataContainer


class Path(DataContainer):
	"""
	TODO: parse Path
	"""

	def __init__(self, data, normalize=True):
		self.auto_normalize = normalize
		self._file_list = list(filter(None, data.split("/")))
		self._cache = data

	def _build_str(self):
		return self._cache

	def __build_cache(self):
		self._cache = "/".join(self._file_list)

	def __bool__(self):
		return bool(self._cache)

	@property
	def absolute_path(self):
		p = str(self)
		if p.startswith("/"):
			return p
		return "/%s"%(p)

	def join(self, path):
		if path.startswith("/"):
			self._file_list = path
			self._cache = path
		else:
			self._file_list.extend(filter(None, path.split("/")))
			self.__build_cache()

