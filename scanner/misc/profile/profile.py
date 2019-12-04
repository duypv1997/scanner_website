from scanner.misc.models.model_mixin import ModelMixIn
from scanner.misc.models.profile import Profile as ProfileModel

import json


class Profile(ModelMixIn):
	def __init__(self, data):
		self._profile = self.deserialize(data, ProfileModel)

	@classmethod
	def from_file(cls, path):
		with open(path) as f:
			return Profile(json.load(f))

	def get_fuzzer_configuration(self):
		return self._profile.fuzzer

	def get_networking_configuration(self):
		return self._profile.networking

	def get_plugins_configuration(self):
		return self._profile.plugins

	def get_strategy_configuration(self):
		return self._profile.strategy

	def get_resource_controller_configuration(self):
		return self._profile.resource
