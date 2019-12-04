from scanner.misc.status import CoreMachineStatus
from scanner.misc.utils.queue import QueueEmptyException
from .multithread import CoreThread


class Worker(CoreMachineStatus, CoreThread):
	QUEUE_GET_TIMEOUT = 0.5

	def __init__(self, pool):
		self.task = None
		self.pool = pool
		CoreMachineStatus.__init__(self)
		CoreThread.__init__(self)

	def start(self):
		self.set_status_running()
		CoreThread.start(self)

	def run(self):
		"""
		Run the worker
		1. Get new task from pool
		2. Run the task
		"""
		while self.is_running():
			try:
				task = self.pool.get_task(timeout=self.QUEUE_GET_TIMEOUT)
			except QueueEmptyException:
				continue
			else:
				self.current_task = task
				try:
					task.run()
				except Exception as e:
					raise
			finally:
				self.current_task = None
		self.set_status_stopped()

	def stop(self, force=True):
		if force:
			self.set_status_stopped()
		else:
			self.set_status_stopping()

	def is_idle(self):
		return (self.current_task == None)
