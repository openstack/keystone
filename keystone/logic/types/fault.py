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

import json
from lxml import etree


class IDMFault(Exception):
    "Base Exception type for all auth exceptions"

    def __init__(self, msg, details=None, code=500):
        self.args = (code, msg, details)
        self.code = code
        self.msg = msg
        self.details = details
        self.key = "idmFault"

    @property
    def message(self):
        return self.msg

    def to_xml(self):
        dom = etree.Element(self.key,
                            xmlns="http://docs.openstack.org/idm/api/v1.0")
        dom.set("code", str(self.code))
        msg = etree.Element("message")
        msg.text = self.msg
        dom.append(msg)
        if self.details != None:
            desc = etree.Element("details")
            desc.text = self.details
            dom.append(desc)
        return etree.tostring(dom)

    def to_json(self):
        fault = {}
        fault["message"] = self.msg
        fault["code"] = str(self.code)
        if self.details != None:
            fault["details"] = self.details
        ret = {}
        ret[self.key] = fault
        return json.dumps(ret)


class ServiceUnavailableFault(IDMFault):
    "The auth service is unavailable"

    def __init__(self, msg, details=None, code=503):
        super(ServiceUnavailableFault, self).__init__(msg, details, code)
        self.key = "serviceUnavailable"


class BadRequestFault(IDMFault):
    "Bad user request"

    def __init__(self, msg, details=None, code=400):
        super(BadRequestFault, self).__init__(msg, details, code)
        self.key = "badRequest"


class UnauthorizedFault(IDMFault):
    "User is unauthorized"

    def __init__(self, msg, details=None, code=401):
        super(UnauthorizedFault, self).__init__(msg, details, code)
        self.key = "unauthorized"


class ForbiddenFault(IDMFault):
    "The user is forbidden"

    def __init__(self, msg, details=None, code=403):
        super(ForbiddenFault, self).__init__(msg, details, code)
        self.key = "forbidden"


class ItemNotFoundFault(IDMFault):
    "The item is not found"

    def __init__(self, msg, details=None, code=404):
        super(ItemNotFoundFault, self).__init__(msg, details, code)
        self.key = "itemNotFound"


class TenantDisabledFault(IDMFault):
    "The tenant is disabled"

    def __init__(self, msg, details=None, code=403):
        super(TenantDisabledFault, self).__init__(msg, details, code)
        self.key = "tenantDisabled"


class TenantConflictFault(IDMFault):
    "The tenant already exists?"

    def __init__(self, msg, details=None, code=409):
        super(TenantConflictFault, self).__init__(msg, details, code)
        self.key = "tenantConflict"


class TenantGroupConflictFault(IDMFault):
    "The tenant Group already exists?"

    def __init__(self, msg, details=None, code=409):
        super(TenantGroupConflictFault, self).__init__(msg, details, code)
        self.key = "tenantGroupConflict"


class OverlimitFault(IDMFault):
    "A limit has been exceeded"

    def __init__(self, msg, details=None, code=409, retry_at=None):
        super(OverlimitFault, self).__init__(msg, details, code)
        self.args = (code, msg, details, retry_at)
        self.retry_at = retry_at
        self.key = "overLimit"


class UserConflictFault(IDMFault):
    "The User already exists?"

    def __init__(self, msg, details=None, code=409):
        super(UserConflictFault, self).__init__(msg, details, code)
        self.key = "userConflict"


class UserDisabledFault(IDMFault):
    "The user is disabled"

    def __init__(self, msg, details=None, code=403):
        super(UserDisabledFault, self).__init__(msg, details, code)
        self.key = "userDisabled"


class EmailConflictFault(IDMFault):
    "The Email already exists?"

    def __init__(self, msg, details=None, code=409):
        super(EmailConflictFault, self).__init__(msg, details, code)
        self.key = "emailConflict"


class UserGroupConflictFault(IDMFault):
    "The user already exists in group?"

    def __init__(self, msg, details=None, code=409):
        super(UserGroupConflictFault, self).__init__(msg, details, code)
        self.key = "userGroupConflict"
