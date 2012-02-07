# vim: tabstop=4 shiftwidth=4 softtabstop=4
#
# Copyright (C) 2011 OpenStack LLC.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Model descriptions.

Unless marked otherwise, all fields are strings.

"""


class Model(dict):
    """Base model class."""

    @property
    def known_keys(cls):
        return cls.required_keys + cls.optional_keys


class User(Model):
    """User object.

    Required keys:
        id
        name

    Optional keys:
        password
        description
        email
        enabled (bool, default True)
    """

    required_keys = ('id', 'name')
    optional_keys = ('password', 'description', 'email', 'enabled')


class Tenant(Model):
    """Tenant object.

    Required keys:
        id
        name

    Optional Keys:
        description
        enabled (bool, default True)

    """

    required_keys = ('id', 'name')
    optional_keys = ('description', 'enabled')


class Role(Model):
    """Role object.

    Required keys:
        id
        name

    """

    required_keys = ('id', 'name')
    optional_keys = tuple()
