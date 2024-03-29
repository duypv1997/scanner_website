# coding: utf-8



import pprint
import re  # noqa: F401

import six

from scanner.misc.models.profile_fuzzing_config import ProfileFuzzingConfig  # noqa: F401,E501
from scanner.misc.models.profile_metadata import ProfileMetadata  # noqa: F401,E501
from scanner.misc.models.profile_networking_config import ProfileNetworkingConfig  # noqa: F401,E501
from scanner.misc.models.profile_plugins_list import ProfilePluginsList  # noqa: F401,E501
from scanner.misc.models.profile_resource_controller_config import ProfileResourceControllerConfig  # noqa: F401,E501
from scanner.misc.models.profile_strategy_config import ProfileStrategyConfig  # noqa: F401,E501


class Profile(object):
    """NOTE: This class is auto generated by the swagger code generator program.

    Do not edit the class manually.
    """

    """
    Attributes:
      swagger_types (dict): The key is attribute name
                            and the value is attribute type.
      attribute_map (dict): The key is attribute name
                            and the value is json key in definition.
    """
    swagger_types = {
        'metadata': 'ProfileMetadata',
        'plugins': 'ProfilePluginsList',
        'networking': 'ProfileNetworkingConfig',
        'fuzzer': 'ProfileFuzzingConfig',
        'strategy': 'ProfileStrategyConfig',
        'resource': 'ProfileResourceControllerConfig'
    }

    attribute_map = {
        'metadata': 'metadata',
        'plugins': 'plugins',
        'networking': 'networking',
        'fuzzer': 'fuzzer',
        'strategy': 'strategy',
        'resource': 'resource'
    }

    def __init__(self, metadata=None, plugins=None, networking=None, fuzzer=None, strategy=None, resource=None):  # noqa: E501
        """Profile - a model defined in Swagger"""  # noqa: E501

        self._metadata = None
        self._plugins = None
        self._networking = None
        self._fuzzer = None
        self._strategy = None
        self._resource = None
        self.discriminator = None

        if metadata is not None:
            self.metadata = metadata
        if plugins is not None:
            self.plugins = plugins
        if networking is not None:
            self.networking = networking
        if fuzzer is not None:
            self.fuzzer = fuzzer
        if strategy is not None:
            self.strategy = strategy
        if resource is not None:
            self.resource = resource

    @property
    def metadata(self):
        """Gets the metadata of this Profile.  # noqa: E501


        :return: The metadata of this Profile.  # noqa: E501
        :rtype: ProfileMetadata
        """
        return self._metadata

    @metadata.setter
    def metadata(self, metadata):
        """Sets the metadata of this Profile.


        :param metadata: The metadata of this Profile.  # noqa: E501
        :type: ProfileMetadata
        """

        self._metadata = metadata

    @property
    def plugins(self):
        """Gets the plugins of this Profile.  # noqa: E501


        :return: The plugins of this Profile.  # noqa: E501
        :rtype: ProfilePluginsList
        """
        return self._plugins

    @plugins.setter
    def plugins(self, plugins):
        """Sets the plugins of this Profile.


        :param plugins: The plugins of this Profile.  # noqa: E501
        :type: ProfilePluginsList
        """

        self._plugins = plugins

    @property
    def networking(self):
        """Gets the networking of this Profile.  # noqa: E501


        :return: The networking of this Profile.  # noqa: E501
        :rtype: ProfileNetworkingConfig
        """
        return self._networking

    @networking.setter
    def networking(self, networking):
        """Sets the networking of this Profile.


        :param networking: The networking of this Profile.  # noqa: E501
        :type: ProfileNetworkingConfig
        """

        self._networking = networking

    @property
    def fuzzer(self):
        """Gets the fuzzer of this Profile.  # noqa: E501


        :return: The fuzzer of this Profile.  # noqa: E501
        :rtype: ProfileFuzzingConfig
        """
        return self._fuzzer

    @fuzzer.setter
    def fuzzer(self, fuzzer):
        """Sets the fuzzer of this Profile.


        :param fuzzer: The fuzzer of this Profile.  # noqa: E501
        :type: ProfileFuzzingConfig
        """

        self._fuzzer = fuzzer

    @property
    def strategy(self):
        """Gets the strategy of this Profile.  # noqa: E501


        :return: The strategy of this Profile.  # noqa: E501
        :rtype: ProfileStrategyConfig
        """
        return self._strategy

    @strategy.setter
    def strategy(self, strategy):
        """Sets the strategy of this Profile.


        :param strategy: The strategy of this Profile.  # noqa: E501
        :type: ProfileStrategyConfig
        """

        self._strategy = strategy

    @property
    def resource(self):
        """Gets the resource of this Profile.  # noqa: E501


        :return: The resource of this Profile.  # noqa: E501
        :rtype: ProfileResourceControllerConfig
        """
        return self._resource

    @resource.setter
    def resource(self, resource):
        """Sets the resource of this Profile.


        :param resource: The resource of this Profile.  # noqa: E501
        :type: ProfileResourceControllerConfig
        """

        self._resource = resource

    def to_dict(self):
        """Returns the model properties as a dict"""
        result = {}

        for attr, _ in six.iteritems(self.swagger_types):
            value = getattr(self, attr)
            if isinstance(value, list):
                result[attr] = list(map(
                    lambda x: x.to_dict() if hasattr(x, "to_dict") else x,
                    value
                ))
            elif hasattr(value, "to_dict"):
                result[attr] = value.to_dict()
            elif isinstance(value, dict):
                result[attr] = dict(map(
                    lambda item: (item[0], item[1].to_dict())
                    if hasattr(item[1], "to_dict") else item,
                    value.items()
                ))
            else:
                result[attr] = value

        return result

    def to_str(self):
        """Returns the string representation of the model"""
        return pprint.pformat(self.to_dict())

    def __repr__(self):
        """For `print` and `pprint`"""
        return self.to_str()

    def __eq__(self, other):
        """Returns true if both objects are equal"""
        if not isinstance(other, Profile):
            return False

        return self.__dict__ == other.__dict__

    def __ne__(self, other):
        """Returns true if both objects are not equal"""
        return not self == other
