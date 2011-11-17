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


class IdentityFault(Exception):
    """Base Exception type for all auth exceptions"""

    def __init__(self, msg, details=None, code=500):
        self.args = (code, msg, details)
        self.code = code
        self.msg = msg
        self.details = details
        self.key = "IdentityFault"

    @property
    def message(self):
        return self.msg

    def to_xml(self):
        dom = etree.Element(self.key,
                        xmlns="http://docs.openstack.org/identity/api/v2.0")
        dom.set("code", str(self.code))
        msg = etree.Element("message")
        msg.text = self.msg
        dom.append(msg)
        if self.details and len(self.details.strip()):
            desc = etree.Element("details")
            desc.text = self.details
            dom.append(desc)
        return etree.tostring(dom)

    def to_json(self):
        fault = {}
        fault["message"] = self.msg
        fault["code"] = str(self.code)
        if self.details and len(self.details.strip()):
            fault["details"] = self.details
        ret = {}
        ret[self.key] = fault
        return json.dumps(ret)


class ServiceUnavailableFault(IdentityFault):
    """The auth service is unavailable"""

    def __init__(self, msg, details=None, code=503):
        super(ServiceUnavailableFault, self).__init__(msg, details, code)
        self.key = "serviceUnavailable"


class BadRequestFault(IdentityFault):
    """Bad user request"""

    def __init__(self, msg, details=None, code=400):
        super(BadRequestFault, self).__init__(msg, details, code)
        self.key = "badRequest"


class UnauthorizedFault(IdentityFault):
    """User is unauthorized"""

    def __init__(self, msg, details=None, code=401):
        super(UnauthorizedFault, self).__init__(msg, details, code)
        self.key = "unauthorized"


class ForbiddenFault(IdentityFault):
    """The user is forbidden"""

    def __init__(self, msg, details=None, code=403):
        super(ForbiddenFault, self).__init__(msg, details, code)
        self.key = "forbidden"


class ItemNotFoundFault(IdentityFault):
    """The item is not found"""

    def __init__(self, msg, details=None, code=404):
        super(ItemNotFoundFault, self).__init__(msg, details, code)
        self.key = "itemNotFound"


class TenantDisabledFault(IdentityFault):
    """The tenant is disabled"""

    def __init__(self, msg, details=None, code=403):
        super(TenantDisabledFault, self).__init__(msg, details, code)
        self.key = "tenantDisabled"


class TenantConflictFault(IdentityFault):
    """The tenant already exists?"""

    def __init__(self, msg, details=None, code=409):
        super(TenantConflictFault, self).__init__(msg, details, code)
        self.key = "tenantConflict"


class OverlimitFault(IdentityFault):
    """A limit has been exceeded"""

    def __init__(self, msg, details=None, code=409, retry_at=None):
        super(OverlimitFault, self).__init__(msg, details, code)
        self.args = (code, msg, details, retry_at)
        self.retry_at = retry_at
        self.key = "overLimit"


class UserConflictFault(IdentityFault):
    """The User already exists?"""

    def __init__(self, msg, details=None, code=409):
        super(UserConflictFault, self).__init__(msg, details, code)
        self.key = "userConflict"


class UserDisabledFault(IdentityFault):
    """The user is disabled"""

    def __init__(self, msg, details=None, code=403):
        super(UserDisabledFault, self).__init__(msg, details, code)
        self.key = "userDisabled"


class EmailConflictFault(IdentityFault):
    """The Email already exists?"""

    def __init__(self, msg, details=None, code=409):
        super(EmailConflictFault, self).__init__(msg, details, code)
        self.key = "emailConflict"


class RoleConflictFault(IdentityFault):
    """The User already exists?"""

    def __init__(self, msg, details=None, code=409):
        super(RoleConflictFault, self).__init__(msg, details, code)
        self.key = "roleConflict"


class ServiceConflictFault(IdentityFault):
    """The Service already exists?"""

    def __init__(self, msg, details=None, code=409):
        super(ServiceConflictFault, self).__init__(msg, details, code)
        self.key = "serviceConflict"
