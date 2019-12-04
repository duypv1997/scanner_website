from scanner.misc.utils.logger import singleton_logger as core_logger
from scanner.core import Scanner


import argparse


def parse_arguments():
	parser = argparse.ArgumentParser(description="vuln scanner")
	parser.add_argument("-p", "--profile-path", dest="profile_path", action="store", help="Profile path")
	parser.add_argument("-u", "--url", dest="target_url", action="store", help="Target URL")
	return parser.parse_args()

def error(msg):
	print >> sys.stderr, msg

def main():
	try:
		args = parse_arguments()
	except argparse.ArgumentTypeError as e:
		error(str(e))
		return 1

	# Setup logger
	# core_logger.set_level("INFO")
	core_logger.set_level("DEBUG")
	core_logger.setup()
	
	# Setup scanner
	scanner = Scanner()
	scanner.set_target(args.target_url)
	scanner.set_profile_from_file(args.profile_path)

	# Start scanner
	scanner.start()


if __name__ == '__main__':
	main()
