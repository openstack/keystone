# Copyright (c) 2010-2011 OpenStack, LLC.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from abc import ABCMeta


class Credentials(object):
    "Base class for all auth credentials."
    __metaclass__ = ABCMeta


class PasswordCredentials(Credentials):
    "Credentials based on username, password, and (optional) tenant_id."

    def __init__(self, username, password, tenant_id):
        self.__username = username
        self.__password = password
        self.__tenant_id = tenant_id

    @property
    def username(self):
        return self.__username

    @property
    def password(self):
        return self.__password

    @property
    def tenant_id(self):
        return self.__password


class Token(object):
    "An auth token."

    def __init__(self, expires, token_id):
        self.__expires = expires
        self.__token_id = token_id

    @property
    def expires(self):
        return self.__expires

    @property
    def token_id(self):
        return self.__token_id


class Group(object):
    "A group, optionally belonging to a tenant."

    def __init__(self, group_id, tenant_id):
        self.__tenant_id = tenant_id
        self.__group_id = group_id

    @property
    def group_id(self):
        return self.__group_id

    @property
    def tenant_id(self):
        return self.__tenant_id


class User(object):
    "A user."

    def __init__(self, username, tenant_id, groups):
        self.__username = username
        self.__tenant_id = tenant_id
        self.__groups = groups

    @property
    def username(self):
        return self.__username

    @property
    def tenant_id(self):
        return self.__tenant_id

    @property
    def groups(self):
        return self.__groups


class AuthData(object):
    "Authentation Infor returned upon successful login."

    def __init__(self, token, user):
        self.__token = token
        self.__user = user

    @property
    def user(self):
        return self.__user

    @property
    def token(self):
        return self.__token
