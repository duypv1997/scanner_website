import logging, os
from logging.handlers import RotatingFileHandler
from distutils.dir_util import mkpath


LOG_LEVEL_STR = {
	"INFO": logging.INFO,
	"WARNING": logging.WARNING,
	"DEBUG": logging.DEBUG,
	"ERROR": logging.ERROR,
}

LOG_FORMAT = logging.Formatter('%(asctime)s %(levelname)s:\t%(message)s')

class Logger:
	"""
	This class is based on logging class, it's logging the entire process of the main program
	"""
	LOG_MAX_SIZE = 100*1024*1024 # 100 MB
	NUM_BACKUPS = 5 

	def __init__(self, name=None, files=[]):
		self.logger = logging.getLogger(name)
		self.files = files
		self.log_format = None

	def setup(self):
		self.log_format = LOG_FORMAT
		self.setup_handlers()

	@staticmethod
	def from_logger(logger):
		return Logger(logger.name)

	def add_output(self, path, rotate=True, **kwargs):
		if path:
			dirname = os.path.dirname(path)
			if not os.path.exists(dirname): 
				mkpath(dirname)
		if rotate:
			# Default 100MB
			size = kwargs.get("max_size", self.LOG_MAX_SIZE)
			backups = kwargs.get("backups", self.NUM_BACKUPS)
			handler = RotatingFileHandler(path, maxBytes=size, backupCount=backups)
		else:
			handler = logging.FileHandler(path)

		if self.log_format:
			handler.setFormatter(self.log_format)
		self.logger.addHandler(handler)

	def setup_handlers(self):
		self.logger.handlers = []
		if self.files:
			for f in self.files:
				self.add_output(f)
		else:
			stream_handler = logging.StreamHandler()
			if self.log_format:
				stream_handler.setFormatter(self.log_format)
			self.logger.addHandler(stream_handler)

	def info(self, msg):
		self.logger.info(msg)

	def warning(self, msg):
		self.logger.warning(msg)

	def debug(self, msg):
		self.logger.debug(msg)

	def error(self, msg):
		self.logger.error(msg)

	def exception(self, msg):
		self.logger.exception(msg)

	def set_level(self, level):
		if level in LOG_LEVEL_STR:
			self.logger.setLevel(LOG_LEVEL_STR[level])


singleton_logger = Logger("Scanner")
