from .response import HTTPResponse
from scanner.misc.utils.timeutils import *
from scanner.knowledge_base.data_container.http.headers import HTTPHeaders
from scanner.misc.threading import RLock

import time, requests, collections, urllib3

urllib3.disable_warnings()


def request_wrapper(func):
	def wrapper(self, *args, **kwargs):
		r = func(self, *args, **kwargs)
		self.update_new_request()
		return HTTPResponse.from_raw_response(r)
	return wrapper

class HTTPRequester:
	DEFAULT_TIMEOUT = 30

	def __init__(self):
		self._request_rate = collections.deque(maxlen=10)
		self._lock = RLock()
		self.headers = {
			"User-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/66.0.3359.117 Safari/537.36",
		}

	@property
	def session(self):
		if not hasattr(self, "_session"):
			self._session = self.new_session()
		return self._session

	def new_session(self):
		s = requests.Session()
		for k, v in self.headers.items():
			if v is not None:
				s.headers[k] = v
		return s

	def send(self, request):
		url = str(request.url)
		post_data = request.post_data
		headers = request.headers
		if isinstance(headers, HTTPHeaders):
			headers = headers.to_dict()
		send_method = getattr(self, request.method)
		return send_method(url=url, headers=headers, data=post_data)

	@request_wrapper
	def GET(self, *args, **kwargs):
		if "cookies" in kwargs:
			self.session.cookies.clear()
		if "timeout" not in kwargs:
			kwargs["timeout"] = self.DEFAULT_TIMEOUT
		kwargs["verify"] = False
		return self.session.get(*args, **kwargs)

	@request_wrapper
	def POST(self, *args, **kwargs):
		if "cookies" in kwargs:
			self.session.cookies.clear()
		if "timeout" not in kwargs:
			kwargs["timeout"] = self.DEFAULT_TIMEOUT
		kwargs["verify"] = False
		return self.session.post(*args, **kwargs)

	@request_wrapper
	def session_GET(self, session, *args, **kwargs):
		if "cookies" in kwargs:
			session.cookies.clear()
		if "timeout" not in kwargs:
			kwargs["timeout"] = self.DEFAULT_TIMEOUT
		kwargs["verify"] = False
		return session.get(*args, **kwargs)

	@request_wrapper
	def session_POST(self, session, *args, **kwargs):
		if "cookies" in kwargs:
			session.cookies.clear()
		if "timeout" not in kwargs:
			kwargs["timeout"] = self.DEFAULT_TIMEOUT
		return session.post(*args, **kwargs)

	@request_wrapper
	def clean_GET(self, *args, **kwargs):
		if "timeout" not in kwargs:
			kwargs["timeout"] = self.DEFAULT_TIMEOUT
		kwargs["verify"] = False
		return requests.get(*args, **kwargs)

	@request_wrapper
	def clean_POST(self, *args, **kwargs):
		if "timeout" not in kwargs:
			kwargs["timeout"] = self.DEFAULT_TIMEOUT
		kwargs["verify"] = False
		return requests.post(*args, **kwargs)

	def get_request_rate(self):
		ct = datetime_to_timestamp(get_current_time())
		if self._request_rate:
			t, c = self._request_rate[-1]
			if t < ct - 1:
				return 0 
			try:
				t1, c1 = self._request_rate[-2]
				assert t1 == t-1
			except (IndexError, AssertionError):
				return c
			else:
				return c1 
		return 0

	def update_new_request(self):
		t = datetime_to_timestamp(get_current_time())
		with self._lock:
			if self._request_rate:
				item = self._request_rate[-1]
				if item[0] == t:
					item[1] += 1
					return
			self._request_rate.append([t, 1])


class MultiThreadHTTPRequester(HTTPRequester):
	@property
	def session(self):
		if not hasattr(self, "_sessions"):
			self._sessions = {}
		thread_id = threading.current_thread().ident
		if thread_id not in self._sessions:
			self._sessions[thread_id] = self.new_session()
		return self._sessions[thread_id]


singleton_multithread_requester_object = None
singleton_requester_object = None

def SingletonRequester():
	global singleton_requester_object
	if singleton_requester_object is None:
		singleton_requester_object = Requester()
	return singleton_requester_object

def SingletonMultiThreadRequester():
	global singleton_multithread_requester_object
	if singleton_multithread_requester_object is None:
		singleton_multithread_requester_object = MultiThreadHTTPRequester()
	return singleton_multithread_requester_object
