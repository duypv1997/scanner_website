from scanner.misc.utils.logger import singleton_logger as core_logger
from scanner.misc.status import CoreMachineStatus
from scanner.misc.utils.queue import Queue, QueueEmptyException
from .worker import Worker
from .task import Task
from .multithread import CoreThread, RLock


class ThreadPool(CoreMachineStatus, CoreThread):
	"""
	                                               |---> worker --->|
	                             --------------    |---> worker --->|
	                --- task --->| task queue |--->|---> worker --->|
	                |            --------------    |---> worker --->|
	------------    |                              |---> worker --->|
	| in_queue |--->|   
	------------    |                       
	                |                       |---> pause
	                --- control signals --->|---> resume
	                                        |---> stop

	Basic usage:
	>>> pool = ThreadPool(pool_size=10)
	>>> tasks = []
	>>> for i in range(10):
	...     task = Task(func, arg1, args)
	...     tasks.append(task)
	...     pool.add_task(task)
	>>> do_some_time_intensive_tasks()
	>>> for t in tasks:
	...     print t, t.result
	>>> pool.join()
	"""
	QUEUE_GET_TIMEOUT = 0.5

	SIG_STOP = 0
	SIG_PAUSE = 1
	SIG_RESUME = 2

	CONTROL_SIGNALS = [
		SIG_STOP,
		SIG_PAUSE,
		SIG_RESUME,
	]

	def __init__(self, pool_size=10, task_queue_size=1000):
		# Internal variables
		self.pool_size = pool_size
		self.task_queue_size = task_queue_size
		self.task_queue = None
		self.in_queue = None
		self.workers = []
		self._in_queue_lock = RLock()

		CoreMachineStatus.__init__(self)
		CoreThread.__init__(self)

	def debug(self, msg):
		core_logger.debug("{}: {}".format(self.__class__.__name__, msg))

	def setup(self):
		self.setup_queue()
		self.setup_workers()

	def setup_queue(self):
		self.task_queue = Queue(self.task_queue_size)
		self.in_queue = Queue(self.task_queue_size)

	def create_worker(self):
		w = Worker(pool=self)
		self.workers.append(w)
		w.start()
		return w

	def setup_workers(self):
		"""
		Remove, or create new workers if pool_size is changed 

		*
		* TODO: Remove only idle workers
		*
		"""
		removed_workers = self.workers[self.pool_size:]
		if removed_workers:
			self.debug("Stopping {} worker(s) ...".format(len(self.workers)))
			for w in removed_workers:
				self.debug("Stopping worker {} ...".format(w.ident))
				w.stop()
			for w in removed_workers:
				w.join()
				self.debug("Worker {} is stopped".format(w.ident))
		else:
			added_workers = self.pool_size - len(self.workers)
			if added_workers > 0:
				self.debug("Creating {} worker(s) ...".format(added_workers))
				for i in range(added_workers):
					w = self.create_worker()
					self.debug("Worker {} is created and started".format(w.ident))
		for w in self.workers:
			w.task_queue = self.task_queue

	@classmethod
	def is_control_signal(cls, item):
		return (item in cls.CONTROL_SIGNALS)

	@classmethod
	def is_task(cls, item):
		return isinstance(item, Task)

	def stop_workers(self):
		for w in self.workers:
			w.stop()

	def join_workers(self):
		for w in self.workers:
			w.join()

	def _handle_stop_signal(self):
		self.set_status_stopping()

	def _handle_control_signal(self, sig):
		"""
		Handled signals: 
			- SIG_STOP
		"""
		if sig == self.SIG_STOP:
			self.debug("Received SIG_STOP signal")
			self._handle_stop_signal()

	def _handle_task(self, task):
		self.task_queue.put(task)

	def stop(self, force=False):
		"""
		Stop the pool
		@param force:
			- False: Send SIG_STOP signal to in_queue
			- True:  Remove all pending tasks, then send SIG_STOP signal to in_queue
		"""
		if self.is_running():
			with self._in_queue_lock:
				if force:
					self._dummy_consume(self.in_queue)
					self._dummy_consume(self.task_queue)
				self.in_queue.put(self.SIG_STOP)

	def run(self):
		"""
		1. Process input from in_queue. Input can be one of the following:
			- Control signal, for now only SIG_STOP will be handled
			- Task object, will be passed to task_queue
		2. There are 2 ways to stop a Threadpool
			- Use stop(force=False) method. This method sends a SIG_STOP signal to Threadpool's in_queue, and ThreadPool will stop after finishing all processing and pending tasks
			- Use stop(force=True) method. ThreadPool will remove all pending tasks and will stop after finishing all processing tasks
		"""
		while self.is_running():
			q = self.in_queue
			try:
				item = q.get(timeout=self.QUEUE_GET_TIMEOUT)
			except QueueEmptyException:
				continue
			else:
				if self.is_control_signal(item):
					self._handle_control_signal(item)
				elif self.is_task(item):
					self._handle_task(item)
				q.task_done()

		# The pool is stopping, join all workers
		self.stop_workers()
		self.join_workers()

		# The threadpool is stopped
		self.set_status_stopped()

	def start(self):
		# Create queue and workers
		self.set_status_running()
		self.setup()

		# Start main thread
		CoreThread.start(self)

	def add_task(self, func, *args, **kwargs):
		with self._in_queue_lock:
			if not self.is_ready_for_task():
				return False
			task = Task(func, *args, **kwargs)
			self.in_queue.put(task)
			return task

	def is_ready_for_task(self):
		return self.is_running()

	def get_task(self, timeout=None):
		try:
			task = self.task_queue.get(timeout=timeout)
		except QueueEmptyException:
			raise
		else:
			self.task_queue.task_done()
			return task

	@staticmethod
	def start_daemon_thread(func, *args, **kwargs):
		t = CoreThread(target=func, args=args, kwargs=kwargs)
		t.daemon = True
		t.start()
		return t

	@staticmethod
	def start_thread(func, *args, **kwargs):
		t = CoreThread(target=func, args=args, kwargs=kwargs)
		t.daemon = False
		t.start()
		return t 

	def is_idle(self):
		if not self.task_queue.empty():
			return False
		for w in self.workers:
			if not w.is_idle():
				return False
		return True

	@staticmethod
	def _dummy_consume(queue):
		while True:
			try:
				queue.get_nowait()
			except QueueEmptyException:
				break
			else:
				queue.task_done()

	wait = CoreThread.join
