import future
import queue


QueueEmptyException = queue.Empty

class Queue(queue.Queue):
	def get_bulk(self, bulk=1, timeout=None):
		results = []
		while len(results) < bulk:
			try:
				results.append(self.get(timeout=timeout))
			except QueueEmptyException:
				break
		return results

	def put_bulk(self, items):
		for item in items:
			self.put(item)
