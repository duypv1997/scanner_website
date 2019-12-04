from scanner.misc.status import CoreMachineStatus
from scanner.misc.utils.logger import singleton_logger as core_logger
from scanner.misc.threading import ThreadPool


class CoreController(CoreMachineStatus):
	def __init__(self, core):
		CoreMachineStatus.__init__(self)
		self.core = core

	def load_config(self, config):
		self.config = config

	def run_service_background(self, func, *args, **kwargs):
		ThreadPool.start_daemon_thread(func, *args, **kwargs)

	def debug(self, msg):
		core_logger.debug("{}: {}".format(self.__class__.__name__, msg))

	def start(self):
		self.set_status_running()
		self.run()

	def stop(self):
		"""
		TODO: handle stop method
		"""
		self.set_status_stopped()

	def run(self):
		return

	def setup(self):
		return

	def join(self):
		return