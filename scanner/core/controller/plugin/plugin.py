from scanner.core.controller.networking.http import HTTPRequest
from scanner.knowledge_base import kb
from scanner.misc.utils.queue import Queue
from scanner.misc.status import CoreMachineStatus
from scanner.misc.utils.logger import singleton_logger as core_logger


class Plugin(CoreMachineStatus):
	NAME = None
	CS_VULN_TEMPLATE_ID = None

	def __init__(self, core):
		CoreMachineStatus.__init__(self)
		self.core = core
		self.options = None

	def set_options(self, options):
		self.options = options

	def start(self):
		self.set_status_running()

	def stop(self):
		self.set_status_stopped()

	def debug(self, msg):
		core_logger.debug("{}: {}".format(self.get_name(), msg))

	def get_name(self):
		return self.NAME or self.__class__.__name__

	@property
	def requester(self):
		return self.core.networking_controller.requester

	def create_http_request(self, *args, **kwargs):
		"""
		Create HTTP request with configured data
		
		TODO: configure the HTTP request
		"""
		http_request = HTTPRequest(*args, **kwargs)
		return http_request

	def save_vuln(self, vuln_template_id=None, traffics=None, attributes=None):
		vuln_template_id = vuln_template_id or self.CS_VULN_TEMPLATE_ID
		return