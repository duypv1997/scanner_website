from scanner.misc.status import CoreSingleStatus

from concurrent.futures import Future


class TaskStatus(CoreSingleStatus):
	S_PENDING = 0x00
	S_PROCESSING = 0x01
	S_COMPLETED = 0x02

	STATUS_STR = {
		S_PENDING: "PENDING",
		S_PROCESSING: "PROCESSING",
		S_COMPLETED: "COMPLETED"
	}

	def is_pending(self):
		return self.has_status(self.S_PENDING)

	def is_processing(self):
		return self.has_status(self.S_PROCESSING)

	def is_completed(self):
		return self.has_status(self.S_COMPLETED)


class Task(TaskStatus):
	def __init__(self, func, *args, **kwargs):
		TaskStatus.__init__(self)
		self.func = func
		self.args = args
		self.kwargs = kwargs
		self._result = Future()

	def run(self):
		self.set_status(TaskStatus.S_PROCESSING)
		try:
			r = self.func(*self.args, **self.kwargs)
		except Exception as e:
			raise
			self._result.set_exception(e)
		else:
			self._result.set_result(r)
			return r
		finally:
			self.set_status(TaskStatus.S_COMPLETED)

	def get_result(self):
		return self._result.result()

	def get_exception(self):
		return self._result.exception()