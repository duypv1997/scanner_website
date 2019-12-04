from scanner.knowledge_base.data_container.http.url import URL


class HTTPRequest(object):
	def __init__(self, url, method="GET", headers=None, post_data=None):
		if isinstance(url, URL):
			self.url = url
		else:
			self.url = URL(url)
		self.method = method
		self.headers = headers
		self.post_data = post_data
