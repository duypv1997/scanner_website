from scanner.core.controller import CoreController
from scanner.core.controller.networking.http import HTTPRequest
from scanner.misc.utils.queue import Queue, QueueEmptyException


class ResourceController(CoreController):
	RESOURCE_IN_QUEUE_GET_TIMEOUT = 0.5

	def __init__(self, core):
		CoreController.__init__(self, core=core)
		self._handling_resource = None

	def setup(self):
		self._resources_in_queue = Queue()
		self._resources_out_queue = Queue()

	def run(self):
		"""
		Seed a Domain resource to resources_in_queue
		"""
		self._seed_first_resource()
		self.run_service_background(self.handle_resources)

	def _seed_first_resource(self):
		seeds = [
			self.core.target,
			self.core.target.domain,
			HTTPRequest(self.core.target),
		]
		for s in seeds:
			self.add_resource(s)

	def add_resource(self, resource):
		self._resources_in_queue.put(resource)

	def add_resources(self, resources):
		for r in resources:
			self._resources_in_queue.put(r)

	def get_resource(self, timeout=None):
		return self._resources_out_queue.get(timeout=timeout)

	def handle_resources(self):
		"""
		- Get resource from in_queue
		- Handle the resource (filter, modify, ...)
		- Send handled resource to out_queue
		#
		# TODO: bulk resources
		#
		"""
		while self.is_running():
			try:
				self._handling_resource = r = self._resources_in_queue.get(timeout=self.RESOURCE_IN_QUEUE_GET_TIMEOUT)
			except QueueEmptyException:
				continue
			else:
				handled_resource = self._handle_resource(r)
				if handled_resource:
					self._resources_out_queue.put(handled_resource)
				self._handling_resource = None

	def _handle_resource(self, resource):
		self.debug("Handling resource: %s ..."%(resource))
		return resource

	def queues_empty(self):
		return self._resources_in_queue.empty() and self._resources_out_queue.empty()

	def is_handling_resource(self):
		if self._handling_resource:
			return True
		return False