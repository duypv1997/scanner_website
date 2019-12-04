class CoreMultiStatus(object):
	STATUS_STR = {}

	def __init__(self):
		self._status = 0

	def set_status(self, status, force=False):
		if force:
			self._status = status
		else:
			self._status |= status

	def unset_status(self, status):
		self._status = (self._status & status)^(self._status)

	def has_status(self, status):
		return bool(self._status & status)

	def get_status_str(self):
		status = []
		for sid, sname in self.STATUS_STR.items():
			if self.has_status(sid):
				status.append(sname)
		return " | ".join(status)


class CoreSingleStatus(CoreMultiStatus):
	def set_status(self, status):
		return CoreMultiStatus.set_status(self, status, force=True)
