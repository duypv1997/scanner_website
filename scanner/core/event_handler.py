import time


class CoreEventHandler(object):
	def __init__(self, core):
		self.core = core

	def run(self):
		try:
			while self.core.is_running():
				time.sleep(0.1)
		except KeyboardInterrupt:
			self.core.stop()
