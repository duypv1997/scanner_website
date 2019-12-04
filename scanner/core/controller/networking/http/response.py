class HTTPResponse(object):
	def __init__(self, status_code, headers, data=None):
		self.status_code = status_code
		self.headers = headers
		self.data = data
			
	@classmethod
	def from_raw_response(cls, response):
		return cls(response.status_code, response.headers, response.text)

	def get_body(self):
		if self.data:
			return str(self.data)
		return ""