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

# pylint: disable=C0103,R0912,R0913,R0914

import json
from lxml import etree
from keystone.logic.types import fault
import keystone.backends.api as db_api
from keystone import utils


class AuthBase(object):
    def __init__(self, tenant_id=None, tenant_name=None):
        self.tenant_id = tenant_id
        self.tenant_name = tenant_name

    @staticmethod
    def _validate_auth(obj, *valid_keys):
        if not 'auth' in obj:
            raise fault.BadRequestFault('Expecting auth')

        auth = obj.get('auth')

        for key in auth:
            if not key in valid_keys:
                raise fault.BadRequestFault('Invalid attribute(s): %s' % key)

        if auth.get('tenantId') and auth.get('tenantName'):
            raise fault.BadRequestFault(
                'Expecting either Tenant ID or Tenant Name, but not both')

        return auth

    @staticmethod
    def _validate_key(obj, key, *required_keys):
        if not key in obj:
            raise fault.BadRequestFault('Expecting %s' % key)

        ret = obj[key]

        for skey in ret:
            if not skey in required_keys:
                raise fault.BadRequestFault('Invalid attribute(s): %s' % skey)

        for required_key in required_keys:
            if not ret.get(required_key):
                raise fault.BadRequestFault('Expecting %s:%s' %
                                            (key, required_key))
        return ret


class AuthWithUnscopedToken(AuthBase):
    def __init__(self, token_id, tenant_id=None, tenant_name=None):
        super(AuthWithUnscopedToken, self).__init__(tenant_id, tenant_name)
        self.token_id = token_id

    @staticmethod
    def from_xml(xml_str):
        try:
            dom = etree.Element("root")
            dom.append(etree.fromstring(xml_str))
            root = dom.find("{http://docs.openstack.org/identity/api/v2.0}"
                "auth")
            if root is None:
                raise fault.BadRequestFault("Expecting auth")
            token = root.find("{http://docs.openstack.org/identity/api/v2.0}"
                "token")
            if token is None:
                raise fault.BadRequestFault("Expecting token")

            token_id = token.get("id")
            tenant_id = root.get("tenantId")
            tenant_name = root.get("tenantName")
            utils.check_empty_string(token_id, "Expecting a token id.")
            if tenant_id and tenant_name:
                raise fault.BadRequestFault(
                    "Expecting either Tenant ID or Tenant Name, but not both")

            return AuthWithUnscopedToken(token_id, tenant_id, tenant_name)
        except etree.LxmlError as e:
            raise fault.BadRequestFault("Cannot parse password access", str(e))

    @staticmethod
    def from_json(json_str):
        try:
            obj = json.loads(json_str)

            auth = AuthBase._validate_auth(obj, 'tenantId', 'tenantName',
                                           'token')
            token = AuthBase._validate_key(auth, 'token', 'id')

            return AuthWithUnscopedToken(token['id'],
                                         auth.get('tenantId'),
                                         auth.get('tenantName'))
        except (ValueError, TypeError) as e:
            raise fault.BadRequestFault("Cannot parse auth", str(e))


class AuthWithPasswordCredentials(AuthBase):
    def __init__(self, username, password, tenant_id=None, tenant_name=None):
        super(AuthWithPasswordCredentials, self).__init__(tenant_id,
                                                          tenant_name)
        self.username = username
        self.password = password

    @staticmethod
    def from_xml(xml_str):
        try:
            dom = etree.Element("root")
            dom.append(etree.fromstring(xml_str))
            root = dom.find("{http://docs.openstack.org/identity/api/v2.0}"
                            "auth")
            if root is None:
                raise fault.BadRequestFault("Expecting auth")
            tenant_id = root.get("tenantId")
            tenant_name = root.get("tenantName")
            password_credentials = \
                root.find("{http://docs.openstack.org/identity/api/v2.0}"
                "passwordCredentials")
            if password_credentials is None:
                raise fault.BadRequestFault("Expecting passwordCredentials")
            username = password_credentials.get("username")
            utils.check_empty_string(username, "Expecting a username")
            password = password_credentials.get("password")
            utils.check_empty_string(password, "Expecting a password")

            if tenant_id and tenant_name:
                raise fault.BadRequestFault(
                    "Expecting either Tenant ID or Tenant Name, but not both")

            return AuthWithPasswordCredentials(username, password, tenant_id,
                tenant_name)
        except etree.LxmlError as e:
            raise fault.BadRequestFault("Cannot parse password access", str(e))

    @staticmethod
    def from_json(json_str):
        try:
            obj = json.loads(json_str)

            auth = AuthBase._validate_auth(obj, 'tenantId', 'tenantName',
                                           'passwordCredentials', 'token')
            cred = AuthBase._validate_key(auth, 'passwordCredentials',
                                          'username', 'password')

            return AuthWithPasswordCredentials(cred['username'],
                                               cred['password'],
                                               auth.get('tenantId'),
                                               auth.get('tenantName'))
        except (ValueError, TypeError) as e:
            raise fault.BadRequestFault("Cannot parse auth", str(e))


class Ec2Credentials(object):
    """Credentials based on username, access_key, signature and data.

        @type access: str
        @param access: Access key for user in the form of access:project.

        @type signature: str
        @param signature: Signature of the request.

        @type params: dictionary of str
        @param params: Web paramaters used for the signature.

        @type verb: str
        @param verb: Web request verb ('GET' or 'POST').

        @type host: str
        @param host: Web request host string (including port).

        @type path: str
        @param path: Web request path.

     """

    def __init__(self, access, signature, verb,
                 host, path, params):
        self.access = access
        self.signature = signature
        self.verb = verb
        self.host = host
        self.path = path
        self.params = params

    @staticmethod
    def from_xml(xml_str):
        try:
            dom = etree.Element("root")
            dom.append(etree.fromstring(xml_str))
            root = dom.find("{http://docs.openstack.org/identity/api/v2.0}"
                            "auth")
            xmlns = "http://docs.openstack.org/identity/api/ext/OS-KSEC2/v1.0"
            if root is None:
                root = dom.find("{%s}ec2Credentials" % xmlns)
            else:
                root = root.find("{%s}ec2Credentials" % xmlns)
            if root is None:
                raise fault.BadRequestFault("Expecting ec2Credentials")
            access = root.get("key")
            utils.check_empty_string(access, "Expecting an access key.")
            signature = root.get("signature")
            utils.check_empty_string(signature, "Expecting a signature.")
            verb = root.get("verb")
            utils.check_empty_string(verb, "Expecting a verb.")
            host = root.get("host")
            utils.check_empty_string(signature, "Expecting a host.")
            path = root.get("path")
            utils.check_empty_string(signature, "Expecting a path.")
            # TODO(vish): parse xml params
            params = {}
            return Ec2Credentials(access, signature, verb, host, path, params)
        except etree.LxmlError as e:
            raise fault.BadRequestFault("Cannot parse password credentials",
                                        str(e))

    @staticmethod
    def from_json(json_str):
        try:
            root = json.loads(json_str)
            if "auth" in root:
                obj = root['auth']
            else:
                obj = root

            if "OS-KSEC2:ec2Credentials" in obj:
                cred = obj["OS-KSEC2:ec2Credentials"]
            elif "ec2Credentials" in obj:
                cred = obj["ec2Credentials"]
            else:
                raise fault.BadRequestFault("Expecting ec2Credentials")
            # Check that fields are valid
            invalid = [key for key in cred if key not in\
                       ['username', 'access', 'signature', 'params',
                        'verb', 'host', 'path']]
            if invalid != []:
                raise fault.BadRequestFault("Invalid attribute(s): %s"
                                            % invalid)
            if not "access" in cred:
                raise fault.BadRequestFault("Expecting an access key")
            access = cred["access"]
            if not "signature" in cred:
                raise fault.BadRequestFault("Expecting a signature")
            signature = cred["signature"]
            if not "verb" in cred:
                raise fault.BadRequestFault("Expecting a verb")
            verb = cred["verb"]
            if not "host" in cred:
                raise fault.BadRequestFault("Expecting a host")
            host = cred["host"]
            if not "path" in cred:
                raise fault.BadRequestFault("Expecting a path")
            path = cred["path"]
            if not "params" in cred:
                raise fault.BadRequestFault("Expecting params")
            params = cred["params"]
            return Ec2Credentials(access, signature, verb, host, path, params)
        except (ValueError, TypeError) as e:
            raise fault.BadRequestFault("Cannot parse password credentials",
                                        str(e))


# pylint: disable=R0902
class S3Credentials(object):
    """Credentials based on username, access_key, signature and data.

        @type access: str
        @param access: Access key for user in the form of access:project.

        @type signature: str
        @param signature: Signature of the request.

        @type verb: str
        @param verb: Web request verb ('GET' or 'POST').

        @type host: expire
        @param host: Web request expire time.

        @type path: str
        @param path: Web request path.

        @type expire: str
        @param expire: Web request expire.

        @type content_type: str
        @param content_type: Web request content contenttype.

        @type content_md5: str
        @param content_md5: Web request content contentmd5.

        @type xheaders: str
        @param xheaders: Web request content extended headers.

     """

    def __init__(self, access, signature, verb, path, expire, content_type,
                 content_md5, xheaders):
        self.access = access
        self.signature = signature
        self.verb = verb
        self.path = path
        self.expire = expire
        self.content_type = content_type
        self.content_md5 = content_md5
        self.xheaders = xheaders

    @staticmethod
    def from_xml(xml_str):
        try:
            dom = etree.Element("root")
            dom.append(etree.fromstring(xml_str))
            root = dom.find("{http://docs.openstack.org/identity/api/v2.0}"
                            "auth")
            xmlns = "http://docs.openstack.org/identity/api/ext/OS-KSS3/v1.0"
            if root is None:
                root = dom.find("{%s}s3Credentials" % xmlns)
            else:
                root = root.find("{%s}s3Credentials" % xmlns)

            if root is None:
                raise fault.BadRequestFault("Expecting s3Credentials")
            access = root.get("access")
            if access == None:
                raise fault.BadRequestFault("Expecting an access key")
            signature = root.get("signature")
            if signature == None:
                raise fault.BadRequestFault("Expecting a signature")
            verb = root.get("verb")
            if verb == None:
                raise fault.BadRequestFault("Expecting a verb")
            path = root.get("path")
            if path == None:
                raise fault.BadRequestFault("Expecting a path")
            expire = root.get("expire")
            if expire == None:
                raise fault.BadRequestFault("Expecting a expire")
            content_type = root.get("content_type", '')
            content_md5 = root.get("content_md5", '')
            xheaders = root.get("xheaders", None)
            return S3Credentials(access, signature, verb, path, expire,
                                 content_type, content_md5, xheaders)
        except etree.LxmlError as e:
            raise fault.BadRequestFault("Cannot parse password credentials",
                                        str(e))

    @staticmethod
    def from_json(json_str):
        try:
            root = json.loads(json_str)
            if "auth" in root:
                obj = root['auth']
            else:
                obj = root

            if "OS-KSS3:s3Credentials" in obj:
                cred = obj["OS-KSS3:s3Credentials"]
            elif "s3Credentials" in obj:
                cred = obj["s3Credentials"]
            else:
                raise fault.BadRequestFault("Expecting s3Credentials")

            # Check that fields are valid
            invalid = [key for key in cred if key not in\
                       ['username', 'access', 'signature', 'verb', 'expire',
                        'path', 'content_type', 'content_md5', 'xheaders']]
            if invalid != []:
                raise fault.BadRequestFault("Invalid attribute(s): %s"
                                            % invalid)
            if not "access" in cred:
                raise fault.BadRequestFault("Expecting an access key")
            access = cred["access"]
            if not "signature" in cred:
                raise fault.BadRequestFault("Expecting a signature")
            signature = cred["signature"]
            if not "verb" in cred:
                raise fault.BadRequestFault("Expecting a verb")
            verb = cred["verb"]
            if not "path" in cred:
                raise fault.BadRequestFault("Expecting a path")
            path = cred["path"]
            if not "expire" in cred:
                raise fault.BadRequestFault("Expecting a expire")
            expire = cred["expire"]
            content_type = cred.get("content_type", '')
            content_md5 = cred.get("content_md5", '')
            xheaders = cred.get("xheaders", None)
            return S3Credentials(access, signature, verb, path, expire,
                                 content_type, content_md5, xheaders)
        except (ValueError, TypeError) as e:
            raise fault.BadRequestFault("Cannot parse password credentials",
                                        str(e))


class Tenant(object):
    """Provides the scope of a token"""

    def __init__(self, id, name):
        self.id = id
        self.name = name


class Token(object):
    """An auth token."""

    def __init__(self, expires, token_id, tenant=None):
        assert tenant is None or isinstance(tenant, Tenant)

        self.expires = expires
        self.id = token_id
        self.tenant = tenant


class User(object):
    """A user."""

    id = None
    username = None
    tenant_id = None
    tenant_name = None
    rolegrants = None

    def __init__(self, id, username, tenant_id, tenant_name, rolegrants=None):
        self.id = id
        self.username = username
        self.tenant_id = tenant_id
        self.tenant_name = tenant_name
        self.rolegrants = rolegrants


class AuthData(object):
    """Authentation Information returned upon successful login.

        This class handles rendering to JSON and XML. It renders
        the token, the user data, the roles, and the service catalog.

        The list of endpoint URLs in the service catalog can be filtered by
        URL type. For example, when we respond to a public call from a user
        without elevated privileges, the "adminURL" is not returned. The
        url_types paramater in the initializer lists the types to return.
        The actual authorization is done in logic/service.py
    """

    def __init__(self, token, user, base_urls=None, url_types=None):
        self.token = token
        self.user = user
        self.base_urls = base_urls
        if url_types is None:
            self.url_types = ["internal", "public", "admin"]
        else:
            self.url_types = url_types
        self.d = {}
        if self.base_urls is not None:
            self.__convert_baseurls_to_dict()

    def to_xml(self):
        dom = etree.Element("access",
            xmlns="http://docs.openstack.org/identity/api/v2.0")
        token = etree.Element("token",
                             expires=self.token.expires.isoformat())
        token.set("id", self.token.id)
        if self.token.tenant:
            tenant = etree.Element("tenant",
                id=unicode(self.token.tenant.id),
                name=unicode(self.token.tenant.name))
            token.append(tenant)
        dom.append(token)

        user = etree.Element("user",
                id=unicode(self.user.id),
                name=unicode(self.user.username))
        dom.append(user)

        if self.user.rolegrants is not None:
            user.append(self.user.rolegrants.to_dom())

        if self.base_urls is not None and len(self.base_urls) > 0:
            service_catalog = etree.Element("serviceCatalog")
            for key, key_base_urls in self.d.items():
                dservice = db_api.SERVICE.get(key)
                if not dservice:
                    raise fault.ItemNotFoundFault(
                        "The service could not be found")
                service = etree.Element("service",
                                 name=dservice.name, type=dservice.type)
                for base_url in key_base_urls:
                    include_this_endpoint = False
                    endpoint = etree.Element("endpoint")
                    if base_url.region:
                        endpoint.set("region", base_url.region)
                    for url_kind in self.url_types:
                        base_url_item = getattr(base_url, url_kind + "_url")
                        if base_url_item:
                            if '%tenant_id%' in base_url_item:
                                if self.token.tenant:
                                    # Don't return tenant endpoints if token
                                    # not scoped to a tenant
                                    endpoint.set(url_kind + "URL",
                                        base_url_item.replace('%tenant_id%',
                                        str(self.token.tenant.id)))
                                    endpoint.set('tenantId',
                                                 str(self.token.tenant.id))
                                    include_this_endpoint = True
                            else:
                                endpoint.set(url_kind + "URL", base_url_item)
                                include_this_endpoint = True
                    if include_this_endpoint:
                        endpoint.set("id", str(base_url.id))
                        if hasattr(base_url, "version_id"):
                            if base_url.version_id:
                                endpoint.set("versionId",
                                             str(base_url.version_id))
                        service.append(endpoint)
                if service.find("endpoint") is not None:
                    service_catalog.append(service)
            dom.append(service_catalog)
        return etree.tostring(dom)

    def __convert_baseurls_to_dict(self):
        for base_url in self.base_urls:
            if base_url.service_id not in self.d:
                self.d[base_url.service_id] = list()
            self.d[base_url.service_id].append(base_url)

    def to_json(self):
        token = {}
        token["id"] = self.token.id
        token["expires"] = self.token.expires.isoformat()
        if self.token.tenant:
            tenant = {
                'id': unicode(self.token.tenant.id),
                'name': unicode(self.token.tenant.name)}
            token['tenant'] = tenant     # v2.0/Diablo contract
            token['tenants'] = [tenant]  # missed use case in v2.0
        auth = {}
        auth["token"] = token
        auth['user'] = {
            'id': unicode(self.user.id),
            'name': unicode(self.user.username)}

        if self.user.rolegrants is not None:
            auth['user']["roles"] = self.user.rolegrants.to_json_values()

        if self.base_urls is not None and len(self.base_urls) > 0:
            service_catalog = []
            for key, key_base_urls in self.d.items():
                service = {}
                endpoints = []
                for base_url in key_base_urls:
                    include_this_endpoint = False
                    endpoint = {}
                    if base_url.region:
                        endpoint["region"] = base_url.region
                    for url_kind in self.url_types:
                        base_url_item = getattr(base_url, url_kind + "_url")
                        if base_url_item:
                            if '%tenant_id%' in base_url_item:
                                if self.token.tenant:
                                    # Don't return tenant endpoints if token
                                    # not scoped to a tenant
                                    endpoint[url_kind + "URL"] = \
                                    base_url_item.replace('%tenant_id%',
                                            str(self.token.tenant.id))
                                    endpoint['tenantId'] = \
                                            str(self.token.tenant.id)
                                    include_this_endpoint = True
                            else:
                                endpoint[url_kind + "URL"] = base_url_item
                                include_this_endpoint = True
                    if include_this_endpoint:
                        endpoint['id'] = str(base_url.id)
                        if hasattr(base_url, 'version_id'):
                            if base_url.version_id:
                                endpoint['versionId'] = \
                                        str(base_url.version_id)
                        endpoints.append(endpoint)
                        dservice = db_api.SERVICE.get(key)
                        if not dservice:
                            raise fault.ItemNotFoundFault(
                            "The service could not be found for" + str(key))
                if len(endpoints):
                    service["name"] = dservice.name
                    service["type"] = dservice.type
                    service["endpoints"] = endpoints
                    service_catalog.append(service)
            auth["serviceCatalog"] = service_catalog
        ret = {}
        ret["access"] = auth
        return json.dumps(ret)


class ValidateData(object):
    """Authentation Information returned upon successful token validation."""

    token = None
    user = None

    def __init__(self, token, user):
        self.token = token
        self.user = user

    def to_xml(self):
        dom = etree.Element("access",
            xmlns="http://docs.openstack.org/identity/api/v2.0")

        token = etree.Element("token",
            id=unicode(self.token.id),
            expires=self.token.expires.isoformat())

        if self.token.tenant:
            tenant = etree.Element("tenant",
                id=unicode(self.token.tenant.id),
                name=unicode(self.token.tenant.name))
            token.append(tenant)

        user = etree.Element("user",
            id=unicode(self.user.id),
            name=unicode(self.user.username))

        if self.user.tenant_id is not None:
            user.set('tenantId', unicode(self.user.tenant_id))
            if self.user.tenant_name is not None:
                user.set('tenantName', unicode(self.user.tenant_name))

        if self.user.rolegrants is not None:
            user.append(self.user.rolegrants.to_dom())

        dom.append(token)
        dom.append(user)
        return etree.tostring(dom)

    def to_json(self):
        token = {
            "id": unicode(self.token.id),
            "expires": self.token.expires.isoformat()}

        if self.token.tenant:
            tenant = {
                'id': unicode(self.token.tenant.id),
                'name': unicode(self.token.tenant.name)}
            token['tenant'] = tenant     # v2.0/Diablo contract
            token['tenants'] = [tenant]  # missed use case in v2.0

        user = {
            "id": unicode(self.user.id),
            "name": unicode(self.user.username),
            # TODO(ziad) temporary until we are comfortable clients are updated
            "username": unicode(self.user.username)}

        if self.user.tenant_id is not None:
            user['tenantId'] = unicode(self.user.tenant_id)
            if self.user.tenant_name is not None:
                user['tenantName'] = unicode(self.user.tenant_name)

        if self.user.rolegrants is not None:
            user["roles"] = self.user.rolegrants.to_json_values()

        return json.dumps({
            "access": {
                "token": token,
                "user": user}})
