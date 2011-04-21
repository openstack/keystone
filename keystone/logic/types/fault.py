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


class IDMFault(Exception):
    "Base Exception type for all auth exceptions"

    def __init__(self, msg, details=None, code=500):
        self.args = (code, msg, details)
        self.__code = code
        self.__msg = msg
        self.__details = details

    @property
    def message(self):
        return self.__msg

    @property
    def code(self):
        return self.__code

    @property
    def details(self):
        return self.__details


class ServiceUnavailableFault(IDMFault):
    "The auth service is unavailable"

    def __init__(self, msg, details=None, code=503):
        super(ServiceUnavailableFault, self).__init__(msg, details, code)


class BadRequestFault(IDMFault):
    "Bad user request"

    def __init__(self, msg, details=None, code=400):
        super(BadRequestFault, self).__init__(msg, details, code)


class UnauthorizedFault(IDMFault):
    "User is unauthorized"

    def __init__(self, msg, details=None, code=401):
        super(UnauthorizedFault, self).__init__(msg, details, code)


class UserDisabledFault(IDMFault):
    "The user is disabled"

    def __init__(self, msg, details=None, code=403):
        super(UserDisabledFault, self).__init__(msg, details, code)


class ForbiddenFault(IDMFault):
    "The user is forbidden"

    def __init__(self, msg, details=None, code=403):
        super(ForbiddenFault, self).__init__(msg, details, code)


class ItemNotFoundFault(IDMFault):
    "The item is not found"

    def __init__(self, msg, details=None, code=404):
        super(ItemNotFoundFault, self).__init__(msg, details, code)


class TenantConflictFault(IDMFault):
    "The tenant already exists?"

    def __init__(self, msg, details=None, code=409):
        super(TenantConflictFault, self).__init__(msg, details, code)


class OverlimitFault(IDMFault):
    "A limit has been exceeded"

    def __init__(self, msg, details=None, code=409, retry_at=None):
        super(OverlimitFault, self).__init__(msg, details, code)
        self.args = (code, msg, details, retry_at)
        self.__retry_at = retry_at

    @property
    def retry_at(self):
        return self.__retry_at
