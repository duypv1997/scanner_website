from .requester import Requester
from scanner.core.controller import CoreController


class NetworkingController(CoreController):
	def __init__(self, core):
		CoreController.__init__(self, core=core)
		self.requester = Requester()
