from scanner.core.controller.plugin import PluginController
from scanner.core.controller.fuzzer import FuzzingController
from scanner.core.controller.networking import NetworkingController
from scanner.core.controller.resource import ResourceController
from scanner.core.controller.resource import ResourceController
from scanner.core.event_handler import CoreEventHandler
from scanner.exceptions import CoreException
from scanner.misc.profile import Profile
from scanner.knowledge_base.data_container.http.url import URL
from scanner.misc.status import CoreMachineStatus
from scanner.misc.threading import ThreadPool
from scanner.misc.utils.logger import singleton_logger as core_logger
from scanner.misc.utils.queue import QueueEmptyException
from scanner.misc.utils.timeutils import get_current_time, sleep_to


class Scanner(CoreMachineStatus):
	def __init__(self):
		self.target = None
		self.profile = None
		self.controllers = {
			"plugin": PluginController(core=self),
			"networking": NetworkingController(core=self),
			"fuzzer": FuzzingController(core=self),
			"resource": ResourceController(core=self)
		}
		self.event_handler = CoreEventHandler(core=self)

	@property
	def plugin_controller(self):
		return self.controllers["plugin"]

	@property
	def networking_controller(self):
		return self.controllers["networking"]

	@property
	def fuzzing_controller(self):
		return self.controllers["fuzzer"]

	@property
	def resource_controller(self):
		return self.controllers["resource"]

	def set_target(self, target):
		if isinstance(target, URL):
			self.target = target
		else:
			self.target = URL(target)

	def set_profile(self, profile):
		self.profile = profile

	def set_profile_from_file(self, profile_path):
		self.profile = Profile.from_file(profile_path)

	def apply_config(self):
		# Config core
		self.config_core()

		# Config knowledge base
		self.config_db()

		# Config controllers
		self.config_controllers()

	def config_controllers(self):
		# Config fuzzer
		self.config_fuzzer()

		# Config plugins
		self.config_plugin_controller()

		# Config networking
		self.config_networking_controller()

		# Config networking
		self.config_resource_controller()

	def config_core(self):
		self.thread_manager = ThreadPool(10)
		self.thread_manager.start()

	def config_plugin_controller(self):
		core_logger.info("Configuring plugin controller ...")
		plugins_config = self.profile.get_plugins_configuration()
		self.plugin_controller.load_config(plugins_config)
		self.plugin_controller.setup()

	def config_resource_controller(self):
		core_logger.info("Configuring resource controller ...")
		rc_config = self.profile.get_resource_controller_configuration()
		self.resource_controller.load_config(rc_config)
		self.resource_controller.setup()

	def config_networking_controller(self):
		core_logger.info("Configuring networking controller ...")
		networking_config = self.profile.get_networking_configuration()
		self.networking_controller.load_config(networking_config)
		self.networking_controller.setup()

	def config_fuzzer(self):
		core_logger.info("Configuring fuzzer ...")
		fuzzer_config = self.profile.get_fuzzer_configuration()
		self.fuzzing_controller.load_config(fuzzer_config)
		self.fuzzing_controller.setup()

	def config_db(self):
		core_logger.info("Configuring database ...")
		return

	def start(self):
		"""
		The entry point
		*
		* TODO: handle exceptions
		*
		"""
		core_logger.info("Starting scanner ...")
		self.set_status_running()
		try:
			self.apply_config()
			self.start_controllers()
			self.run()
		except KeyboardInterrupt:
			return
		except Exception as e:
			core_logger.error("Start scanner failed: %s"%(str(e)))
			# raise
		finally:
			self.thread_manager.stop()
			self.stop_controllers()
			self.set_status_stopped()
		core_logger.info("Scanner is stopped")

	def stop_controllers(self):
		for c in self.controllers.values():
			c.stop()

	def start_controllers(self):
		for c in self.controllers.values():
			c.start()

	def run(self):
		self.distribute_resources()

	def distribute_resources(self):
		"""
		One of the most important methods
		- Task 1: Get resources produced by plugins, then push to resource controller
		- Task 2: Get resources handled by resource controller, then push to plugins
		"""
		rc = self.resource_controller
		pc = self.plugin_controller
		while self.is_running():
			t = get_current_time()

			# Task 1
			produced_resources = []
			for p in pc.get_running_detector_plugins():
				produced_resources.extend(p.get_resources(bulk=1, timeout=0))
			if produced_resources:
				core_logger.debug("distribute_resources(): found {} new resources".format(len(produced_resources)))

			# Task 2
			try:
				handled_resource = rc.get_resource(timeout=0)
			except QueueEmptyException:
				handled_resource = None
			else:
				core_logger.debug("distribute_resources(): get handled resource: {}".format(handled_resource))

			if produced_resources or handled_resource:
				# Scan is still not done
				# Push produced_resources to resource controller
				rc.add_resources(produced_resources)
				# Push handled_resource to all running detector plugins
				for p in pc.get_running_detector_plugins():
					if p.can_consume_resource(handled_resource):
						self.thread_manager.add_task(p.consume_resource, handled_resource)
			else:
				# No resource is produced by plugins
				# No resource is handled by resource controller
				# Scan is possibly done
				# We have to check the resource controller and plugins
				if self._resource_controller_done() and self._all_detector_plugins_done():
					core_logger.debug("distribute_resources(): done")
					# Scan is done
					break
			sleep_to(t, 0.1)

	def _resource_controller_done(self):
		rc = self.resource_controller
		return rc.queues_empty() and not rc.is_handling_resource()

	def _all_detector_plugins_done(self):
		for p in self.plugin_controller.get_running_detector_plugins():
			if not p.is_idle():
				return False
		return True
