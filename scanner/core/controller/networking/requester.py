from .http import HTTPRequester


class Requester():
	def __init__(self):
		self.http = HTTPRequester()

	def apply_config(self):
		"""
		TODO: set config
		"""
		return
