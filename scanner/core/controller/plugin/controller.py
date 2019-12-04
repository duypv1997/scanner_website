from scanner.core.controller import CoreController

import sys


class PluginController(CoreController):
	PLUGIN_MODULE = "scanner.plugins"
	PLUGIN_TYPES = [ 
		"detector" 
	]

	def __init__(self, core):
		CoreController.__init__(self, core=core)
		self.plugins = {}

	def create_plugin(self, plugin_type, plugin_name, class_name=None):
		full_module_path = ".".join([self.PLUGIN_MODULE, plugin_type, plugin_name])
		try:
			__import__(full_module_path)
		except Exception as e:
			print(e)
			raise
			#
			# TODO: handle exceptions
			#

		class_name = class_name or full_module_path.split(".")[-1]
		try:
			module_inst = sys.modules[full_module_path]
			plugin_class = getattr(module_inst, class_name)
		except Exception as e:
			raise
			#
			# TODO: handle exceptions
			#

		try:
			plugin = plugin_class(core=self.core)
		except Exception as e:
			raise
			#
			# TODO: handle exceptions
			#
		return plugin

	def setup(self):
		for plugin_type in self.PLUGIN_TYPES:
			for plugin_config in self.config.__getattribute__(plugin_type):
				plugin = self.create_plugin(plugin_type=plugin_type, plugin_name=plugin_config.name)
				plugin.set_options(plugin_config.options)
				self.plugins[plugin_type] = self.plugins.get(plugin_type, [])
				self.plugins[plugin_type].append(plugin)

	def start_plugins(self):
		for plugin_type, plugins in self.plugins.items():
			for p in plugins:
				p.start()

	def run(self):
		self.start_plugins()

	def get_running_detector_plugins(self):
		return filter(lambda p: p.is_running(), self.plugins["detector"])

