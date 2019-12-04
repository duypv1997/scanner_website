ERR_INVALID_DATA = "00001"

ERR_PLUGIN_IS_STOPPED = "70001"


class CoreException(Exception):
	ERROR_CODE = ERR_INVALID_DATA

	def __init__(self, **kwargs):
		self.err_data = kwargs


class PluginIsStopped(CoreException):
	ERROR_CODE = ERR_PLUGIN_IS_STOPPED

class InvalidURL(CoreException):
	ERROR_CODE = ERR_INVALID_DATA
