import time, datetime


def get_current_time():
	return datetime.datetime.now()

def get_current_timestamp_millisec():
	return datetime_to_timestamp(get_current_time())*1000
	
def get_current_timestamp():
	return datetime_to_timestamp(get_current_time())

def datetime_to_timestamp(dt):
	return int(time.mktime(dt.timetuple()))

def timestamp_to_datetime(timestamp):
	return datetime.datetime.fromtimestamp(timestamp)

def datetime_to_str(dt):
	return datetime.datetime.fromtimestamp(timestamp)

def get_interval_from(start_dt, end_dt=None):
	if not end_dt:
		end_dt = get_current_time()
	tdelta = end_dt - start_dt
	try:
		return tdelta.total_seconds()
	except AttributeError:
		return tdelta.seconds + tdelta.microseconds/1000000.0

def get_datetime_from(start_dt, interval):
	return start_dt + datetime.timedelta(seconds=interval)

def sleep_to(start_dt, interval):
	delta = interval - get_interval_from(start_dt)
	if delta > 0:
		time.sleep(delta)
