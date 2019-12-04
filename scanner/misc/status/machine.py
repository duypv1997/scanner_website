from .status import CoreSingleStatus


class CoreMachineStatus(CoreSingleStatus):
	S_NONE = 0x00
	S_RUNNING = 0x01
	S_STOPPING = 0x02
	S_STOPPED = 0x04

	STATUS_STR = {
		S_RUNNING: "RUNNING",
		S_STOPPING: "STOPPING",
		S_STOPPED: "STOPPED"
	}

	def is_running(self):
		return self.has_status(self.S_RUNNING)

	def is_stopping(self):
		return self.has_status(self.S_RUNNING)

	def is_stopped(self):
		return self.has_status(self.S_STOPPED)

	def set_status_running(self):
		self.set_status(self.S_RUNNING)

	def set_status_stopping(self):
		self.set_status(self.S_STOPPING)

	def set_status_stopped(self):
		self.set_status(self.S_STOPPED)
