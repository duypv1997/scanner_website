class DataContainer(object):
	def __repr__(self):
		return "<{class_name} {value}>".format(class_name=self.__class__.__name__, value=repr(str(self)))

	def __str__(self):
		return self._build_str()
