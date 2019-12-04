from .plugin import Plugin
from scanner.knowledge_base import kb
from scanner.knowledge_base.vuln import Vuln
from scanner.misc.utils.queue import Queue
from scanner.misc.utils.timeutils import get_current_time, get_interval_from


class DetectorPlugin(Plugin):
	RESOURCE_TYPES = []
	CS_VULN_TEMPLATE_ID = None

	def __init__(self, core):
		Plugin.__init__(self, core)
		self._resources_out_queue = Queue()
		self._is_running_task = False

	def detect(self, resource):
		raise NotImplementedError

	def consume_resource(self, resource):
		self._is_running_task = True
		t = get_current_time()
		try:
			self.detect(resource)
		except Exception as e:
			self.debug("{}.detect({}) failed - time={}".format(self.get_name(), resource, get_interval_from(t)))
			raise
		else:
			self.debug("{}.detect({}) success - time={}".format(self.get_name(), resource, get_interval_from(t)))
		finally:
			self._is_running_task = False

	def save_vuln(self, vuln_template_id=None, vuln_id=None, traffics=None, attributes=None):
		if vuln_template_id is None:
			vuln_template_id = self.CS_VULN_TEMPLATE_ID
		vuln = self.get_vuln_from_template(vuln_template_id)

		# Set attributes for vuln
		vuln.set_traffics(traffics)
		vuln.set_attributes(attributes)

		# Save vuln
		return kb.vuln.save(vuln, vuln_id=vuln_id)

	def save_attribute(self, base_url=None, **attributes):
		return

	@staticmethod
	def get_vuln_from_template(vuln_template_id):
		vuln_template = kb.vuln_template.get(vuln_template_id)
		return Vuln.from_template(vuln_template)

	def can_consume_resource(self, resource):
		return type(resource) in self.RESOURCE_TYPES

	def get_resources(self, bulk=1, timeout=None):
		return self._resources_out_queue.get_bulk(bulk=bulk, timeout=timeout)

	def get_resource(self, timeout=None):
		return self._resources_out_queue.get(timeout=timeout)

	def produce_resource(self, resource):
		return self._resources_out_queue.put(resource)

	def is_idle(self):
		return not self._is_running_task and self._resources_out_queue.empty()
