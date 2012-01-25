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

""" Module that contains all object models

The models are used to hold Keystone 'business' objects and their validation,
serialization, and backend interaction code.

The models are based off of python's dict.

The uses supported are:
    # can be initialized with static properties
    tenant = Tenant(name='A1000')

    # handles writing to correct backend
    tenant.save()

    # static properties
    id = tenant.id
    tenant = None

    # Acts as a dict
    tenant is a dict
    tenant.dict points to the data dict (i.e. tenant["tenant"])

    # can be retrieved by static property
    tenant_by_name = Tenant.get(name='A1000')

    # can be retrieved  by id default, so name not needed
    tenant_by_id = Tenant.get(id)
    assertIsEquals(tenant_by_id, tenant_by_name)

    # handles serialization
    print tenant_by_id
    print tenant_by_id.to_json()    # Keystone latest contract
    print tenant_by_id.to_json_20()  # Keystone 2.0 contract

    Serialization routines can take hints in this format:
        {
            "contract_attributes": ["id", "name", ...],
            "types": [("id", int), (...)]
        }
        attribute/value can be:
        contract_attributes: list of contract attributes (see initializer)
            format is a list of attributes names (ex ['id', 'name'])
        types: list of attribute/type mappings
            format is a list of name/type tuples (ex [('id', int)])
        tags: list of attributes that go into XML tags
            format is a list of attribute names(ex ['description']
        maps: list of attributes to rename
            format is from/to values (ex {'serviceId": "service_id",})
    Default hints can be stored in the class as cls.hints
"""

import json
from lxml import etree

from keystone import utils
from keystone.utils import fault


class AttrDict(dict):
    """Lets us do setattr and getattr since dict does not allow it"""
    pass


class Resource(AttrDict):
    """ Base class for models

    Provides basic functionality that can be overridden """

    hints = {}
    xmlns = None

    def __init__(self, *args, **kw):
        """ Initialize object
        kwargs contain static properties
        """
        super(Resource, self).__init__(*args, **kw)
        # attributes that can be used as attributes. Example:
        #    tenant.id  - here id is a contract attribute
        super(Resource, self).__setattr__("contract_attributes", [])
        if kw:
            self.contract_attributes.extend(kw.keys())
            for name, value in kw.iteritems():
                self[name] = value

    #
    # model properties
    #
    # Override built-in classes to allow for user.id (as well as user["id"])
    # for attributes defined in the Keystone contract
    #
    def __repr__(self):
        return "<%s(%s)>" % (self.__class__.__name__, ', '.join(['%s=%s' %
                (attrib, self[attrib].__repr__()) for attrib in
                self.contract_attributes]))

    def __str__(self):
        """Returns string representation including the class name."""
        return str(self.to_dict())

    def __getattr__(self, name):
        """ Supports reading contract attributes (ex. tenant.id)

        This should only be called if the original call did not match
        an attribute (Python's rules)"""
        if name in self.contract_attributes:
            if name in self:
                return self[name]
            return None
        elif name == 'desc':  # TODO(zns): deprecate this
            # We need to maintain this compatibility with this nasty attribute
            # until we're done refactoring
            return self.description
        else:
            if hasattr(super(Resource, self), name):
                return getattr(super(Resource, self), name)
            else:
                raise AttributeError("'%s' not found on object of class '%s'"
                                     % (name, self.__class__.__name__))

    def __setattr__(self, name, value):
        """ Supports setting contract attributes (ex. tenant.name = 'A1') """

        if name in self.contract_attributes:
            # Put those into the dict (and not as attrs)
            if value is not None:
                self[name] = value
        else:
            super(Resource, self).__setattr__(name, value)

    def __getitem__(self, name):
        if name in self.contract_attributes:
            if super(Resource, self).__contains__(name):
                return super(Resource, self).__getitem__(name)
            return None
        elif name == 'desc':  # TODO(zns): deprecate this
            # We need to maintain this compatibility with this nasty attribute
            # until we're done refactoring
            return self.description
        elif name == self.__class__.__name__.lower():
            # Supports using dict syntax to access the attributes of the
            # class. Ex: Resource(id=1)['resource']['id']
            return self
        else:
            return super(Resource, self).__getitem__(name)

    def __contains__(self, key):
        if key in self.contract_attributes:
            return True
        return super(Resource, self).__contains__(key)

    #
    # Serialization Functions - may be moved to a different class
    #
    def to_dict(self, model_name=None, hints=None):
        """ For compatibility with logic.types """
        if model_name is None:
            model_name = self.__class__.__name__.lower()
        result = self.strip_null_fields(self.copy())
        if hints is None:
            hints = self.hints
        if hints:
            if "types" in hints:
                Resource.apply_type_mappings(
                    result,
                    hints["types"])
            if "maps" in hints:
                Resource.apply_name_mappings(
                    result,
                    hints["maps"])
        return {model_name: result}

    def to_json(self, hints=None, model_name=None):
        """ Serializes object to json - implies latest Keystone contract """
        d = self.to_dict(model_name=model_name)
        if hints is None:
            hints = self.hints
        if hints:
            if "types" in hints:
                Resource.apply_type_mappings(
                    d[model_name or self.__class__.__name__.lower()],
                    hints["types"])
            if "maps" in hints:
                Resource.apply_name_mappings(
                    d[model_name or self.__class__.__name__.lower()],
                    hints["maps"])
        return json.dumps(d)

    def to_xml(self, hints=None, model_name=None):
        """ Serializes object to XML string
            - implies latest Keystone contract
            :param hints: see introduction on format"""
        if hints is None:
            hints = self.hints
        dom = self.to_dom(hints=hints, model_name=model_name)
        return etree.tostring(dom)

    def to_dom(self, xmlns=None, hints=None, model_name=None):
        """ Serializes object to XML objec
        - implies latest Keystone contract
        :param xmlns: accepts an optional namespace for XML
        :param tags: accepts a list of attribute names that should go into XML
        tags instead of attributes
        """
        if xmlns is None:
            xmlns = self.xmlns
        if hints is None:
            hints = self.hints
        if model_name is None:
            model_name = self.__class__.__name__.lower()
        if xmlns:
            dom = etree.Element(model_name, xmlns=xmlns)
        else:
            dom = etree.Element(model_name)
        Resource.write_dict_to_xml(self, dom, hints)
        return dom

    #
    # Deserialization functions
    #
    @classmethod
    def from_json(cls, json_str, hints=None, model_name=None):
        """ Deserializes object from json - assumes latest Keystone
        contract
        """
        if hints is None:
            hints = cls.hints
        try:
            obj = json.loads(json_str)
            if model_name is None:
                model_name = cls.__name__.lower()
            if model_name in obj:
                # Ignore class name if it is there
                obj = obj[model_name]
            if hints and ('maps' in hints):
                name_mappings = hints['maps']
                if name_mappings:
                    Resource.reverse_name_mappings(obj, name_mappings)
            model_object = None
            if hints:
                if 'contract_attributes' in hints:
                    # build mapping and instantiate object with
                    # contract_attributes provided
                    params = {}
                    for name in hints['contract_attributes']:
                        if name in obj:
                            params[name] = obj[name]
                        else:
                            params[name] = None
                    model_object = cls(**params)
            if model_object is None:
                model_object = cls()
            model_object.update(obj)

            if hints and ('types' in hints):
                type_mappings = hints['types']
                Resource.apply_type_mappings(model_object, type_mappings)
            return model_object
        except (ValueError, TypeError) as e:
            raise fault.BadRequestFault("Cannot parse '%s' json" % \
                                        cls.__name__, str(e))

    @classmethod
    def from_xml(cls, xml_str, hints=None):
        """ Deserializes object from XML - assumes latest Keystone
        contract """
        if hints is None:
            hints = cls.hints
        try:
            object = etree.fromstring(xml_str)
            model_object = None
            type_mappings = None
            name_mappings = None
            if hints:
                if 'types' in hints:
                    type_mappings = hints['types']
                if 'contract_attributes' in hints:
                    # build mapping and instantiate object with
                    # contract_attributes provided
                    params = {}
                    for name in hints['contract_attributes']:
                        params[name] = object.get(name, None)
                    model_object = cls(**params)
                if 'maps' in hints:
                    name_mappings = hints['maps']
            if model_object is None:
                model_object = cls()
            cls.write_xml_to_dict(object, model_object)
            if type_mappings:
                Resource.apply_type_mappings(model_object, type_mappings)
            if name_mappings:
                Resource.reverse_name_mappings(model_object, name_mappings)
            return model_object
        except etree.LxmlError as e:
            raise fault.BadRequestFault("Cannot parse '%s' xml" % cls.__name__,
                                        str(e))

    #
    # Validation calls
    #
    def validate(self):
        """ Validates object attributes. Raises error if object not valid

        This calls inspect() in fail_fast mode, so it gets back the first
        validation error and raises it. It is up to the code in inspect()
        to determine what validations take precedence and are returned
        first

        :returns: True if no validation errors raise"""
        errors = self.inspect(fail_fast=True)
        if errors:
            raise errors[0][0](errors[0][1])
        return True

    # pylint: disable=W0613, R0201
    def inspect(self, fail_fast=None):
        """ Validates and retuns validation results without raising any errors
        :param fail_fast" return after first validation failure

        :returns: [(faultClass, message), ...], ordered by relevance
            - if None, then no errors found
        """
        return []

    #
    # Formatting, hint processing functions
    #

    @staticmethod
    def strip_null_fields(dict_object):
        """ Strips null fields from dict"""
        for k, v in dict_object.items():
            if v is None:
                del dict_object[k]
        return dict_object

    @staticmethod
    def write_dict_to_xml(dict_object, xml, hints=None):
        """ Attempts to convert a dict into XML as best as possible.
        Converts named keys and attributes and recursively calls for
        any values are are embedded dicts

        :param hints: handles tags (a list of attribute names that should go
            into XML tags instead of attributes) and maps
        """
        tags = []
        rename = []
        maps = {}
        if hints is not None:
            if 'tags' in hints:
                tags = hints['tags']
            if 'maps' in hints:
                maps = hints['maps']
                rename = maps.values()
        for name, value in dict_object.iteritems():
            if name in rename:
                name = maps.keys()[rename.index(name)]
            if isinstance(value, dict):
                element = etree.SubElement(xml, name)
                Resource.write_dict_to_xml(value, element)
            elif name in tags:
                element = xml.find(name)
                if isinstance(value, dict):
                    if element is None:
                        element = etree.SubElement(xml, name)
                    Resource.write_dict_to_xml(value, element)
                else:
                    if value is not None:
                        if element is None:
                            element = etree.SubElement(xml, name)
                        element.text = str(value)
            else:
                if value is not None:
                    if isinstance(value, dict):
                        Resource.write_dict_to_xml(value, xml)
                    elif isinstance(value, bool):
                        xml.set(name, str(value).lower())
                    else:
                        xml.set(name, str(value))
                else:
                    if name in xml:
                        del xml.attrib[name]

    @staticmethod
    def write_xml_to_dict(xml, dict_object):
        """ Attempts to update a dict with XML as best as possible."""
        for key, value in xml.items():
            dict_object[key] = value
        for element in xml.iterdescendants():
            name = element.tag
            if "}" in name:
                #trim away namespace if it is there
                name = name[name.rfind("}") + 1:]
            if element.attrib == {}:
                dict_object[name] = element.text
            else:
                dict_object[name] = {}
                Resource.write_xml_to_dict(element, dict_object[element.tag])

    @staticmethod
    def apply_type_mappings(target, type_mappings):
        """Applies type mappings to dict values"""
        if type_mappings:
            for name, type in type_mappings:
                if type is int:
                    target[name] = int(target[name])
                elif issubclass(type, basestring):
                    # Move sub to string
                    if name in target:
                        value = target[name]
                        if isinstance(value, dict):
                            value = value[0]
                        if value:
                            target[name] = str(value)
                elif type is bool:
                    target[name] = str(target[name]).lower() not in ['0',
                                                                     'false']
                else:
                    raise NotImplementedError("Model type mappings cannot \
                                handle '%s' types" % type.__name__)

    @staticmethod
    def apply_name_mappings(target, name_mappings):
        """ Applies name mappings to dict values """
        if name_mappings:
            for outside, inside in name_mappings.iteritems():
                if inside in target:
                    target[outside] = target.pop(inside)

    @staticmethod
    def reverse_name_mappings(target, name_mappings):
        """ Extracts names from mappings to dict values """
        if name_mappings:
            for outside, inside in name_mappings.iteritems():
                if outside in target:
                    target[inside] = target.pop(outside)

    #
    # Backend management
    #
    def save(self):
        """ Handles finding correct backend and writing to it
        Supports both saving new object (create) and updating an existing one
        """
        #if self.status == 'new':
        #    #backends[find the class].create(self)
        #elif self.status == 'existing':
        #    #backends[find the class].update(self)
        pass

    def delete(self):
        """ Handles finding correct backend and deleting object from it """
        pass

    @classmethod
    def get(cls, id=None, *args, **kw):
        # backends[find the class].get(id, *args, **kw)
        return cls(*args, **kw)


class Service(Resource):
    """ Service model """
    def __init__(self, id=None, name=None, type=None, description=None,
                 owner_id=None, *args, **kw):
        super(Service, self).__init__(id=id, name=name, type=type,
                                      description=description,
                                      owner_id=owner_id, *args, **kw)
        # pylint: disable=E0203
        if isinstance(self.id, int):
            self.id = str(self.id)

    def to_dict(self, model_name=None):
        if model_name is None:
            model_name = 'OS-KSADM:service'
        return super(Service, self).to_dict(model_name=model_name)

    def to_dom(self, xmlns=None, hints=None, model_name=None):
        if xmlns is None:
            xmlns = "http://docs.openstack.org/identity/api/ext/OS-KSADM/v1.0"
        return super(Service, self).to_dom(xmlns, hints=hints,
                                           model_name=model_name)

    @classmethod
    def from_json(cls, json_str, hints=None, model_name=None):
        if model_name is None:
            model_name = 'OS-KSADM:service'
        result = super(Service, cls).from_json(json_str, hints=hints,
                                              model_name=model_name)
        result.validate()  # TODO(zns): remove; compatibility with logic.types
        return result

    @classmethod
    def from_xml(cls, xml_str, hints=None):
        result = super(Service, cls).from_xml(xml_str, hints=hints)
        result.validate()  # TODO(zns): remove; compatibility with logic.types
        return result

    def inspect(self, fail_fast=None):
        result = super(Service, self).inspect(fail_fast)
        if fail_fast and result:
            return result

        # Check that fields are valid
        invalid = [key for key in result if key not in
                   ['id', 'name', 'type', 'description', 'owner_id']]
        if invalid:
            result.append((fault.BadRequestFault, "Invalid attribute(s): %s"
                                        % invalid))
            if fail_fast:
                return result

        if utils.is_empty_string(self.name):
            result.append((fault.BadRequestFault, "Expecting Service Name"))
            if fail_fast:
                return result

        if utils.is_empty_string(self.type):
            result.append((fault.BadRequestFault, "Expecting Service Type"))
            if fail_fast:
                return result
        return result


class Services(object):
    "A collection of services."

    def __init__(self, values, links):
        self.values = values
        self.links = links

    def to_xml(self, model_name=None):
        dom = etree.Element("services")
        dom.set(u"xmlns",
            "http://docs.openstack.org/identity/api/ext/OS-KSADM/v1.0")

        for t in self.values:
            dom.append(t.to_dom(model_name=model_name))

        for t in self.links:
            dom.append(t.to_dom(model_name=model_name))

        return etree.tostring(dom)

    def to_json(self, model_name=None):
        services = [t.to_dict()["OS-KSADM:service"]
                    for t in self.values]
        services_links = [t.to_dict()["links"]
                    for t in self.links]
        return json.dumps({"OS-KSADM:services": services,
            "OS-KSADM:services_links": services_links})


class Tenant(Resource):
    """ Tenant model """
    # pylint: disable=E0203,C0103
    def __init__(self, id=None, name=None, description=None, enabled=None,
                 *args, **kw):
        super(Tenant, self).__init__(id=id, name=name,
                                      description=description, enabled=enabled,
                                      *args, **kw)
        if isinstance(self.id, int):
            self.id = str(self.id)
        if isinstance(self.enabled, basestring):
            self.enabled = self.enabled.lower() == 'true'

    @classmethod
    def from_xml(cls, xml_str, hints=None):
        if hints is None:
            hints = {}
        if 'contract_attributes' not in hints:
            hints['contract_attributes'] = ['id', 'name', 'description',
                                           'enabled']
        if 'tags' not in hints:
            hints['tags'] = ["description"]
        return super(Tenant, cls).from_xml(xml_str, hints=hints)

    def to_dom(self, xmlns=None, hints=None, model_name=None):
        if hints is None:
            hints = {}
        if 'tags' not in hints:
            hints['tags'] = ["description"]
        if xmlns is None:
            xmlns = "http://docs.openstack.org/identity/api/v2.0"

        return super(Tenant, self).to_dom(xmlns=xmlns, hints=hints,
                                          model_name=model_name)

    def to_xml(self, hints=None, model_name=None):
        if hints is None:
            hints = {}
        if 'tags' not in hints:
            hints['tags'] = ["description"]
        return super(Tenant, self).to_xml(hints=hints, model_name=model_name)

    def to_json(self, hints=None, model_name=None):
        if hints is None:
            hints = {}
        return super(Tenant, self).to_json(hints=hints, model_name=model_name)


class User(Resource):
    """ User model

    Attribute Notes:
    default_tenant_id (formerly tenant_id): this attribute can be enabled or
        disabled by configuration. When enabled, any authentication call
        without a tenant gets authenticated to this tenant.
    """
    # pylint: disable=R0913
    def __init__(self, id=None, password=None, name=None,
                 tenant_id=None,
                 email=None, enabled=None,
                 *args, **kw):
        super(User, self).__init__(id=id, password=password, name=name,
                        tenant_id=tenant_id, email=email,
                        enabled=enabled, *args, **kw)

    def to_json(self, hints=None, model_name=None):
        results = super(User, self).to_json(hints, model_name=model_name)
        assert 'password":' not in results
        return results

    def to_xml(self, hints=None):
        results = super(User, self).to_xml(hints)
        assert 'password"=' not in results
        return results


class EndpointTemplate(Resource):
    """ EndpointTemplate model """
    # pylint: disable=R0913
    def __init__(self, id=None, region=None, service_id=None, public_url=None,
            admin_url=None, internal_url=None, enabled=None, is_global=None,
            version_id=None, version_list=None, version_info=None, *args,
            **kw):
        super(EndpointTemplate, self).__init__(id=id, region=region,
                service_id=service_id, public_url=public_url,
                admin_url=admin_url, internal_url=internal_url,
                enabled=enabled, is_global=is_global, version_id=version_id,
                version_list=version_list, version_info=version_info, *args,
                **kw)


class Endpoint(Resource):
    """ Endpoint model """
    # pylint: disable=R0913
    def __init__(self, id=None, endpoint_template_id=None, tenant_id=None,
            *args, **kw):
        super(Endpoint, self).__init__(id=id, tenant_id=tenant_id,
                endpoint_template_id=endpoint_template_id, *args, **kw)


class Role(Resource):
    """ Role model """
    hints = {"maps":
                {"userId": "user_id",
                "roleId": "role_id",
                "serviceId": "service_id",
                "tenantId": "tenant_id"},
            "contract_attributes": ['id', 'name', 'service_id',
                                           'tenant_id', 'description'],
            "types": [('id', basestring), ('service_id', basestring)],
        }
    xmlns = "http://docs.openstack.org/identity/api/v2.0"

    def __init__(self, id=None, name=None, description=None, service_id=None,
                 tenant_id=None, *args, **kw):
        super(Role, self).__init__(id=id, name=name,
                                   description=description,
                                   service_id=service_id,
                                   tenant_id=tenant_id,
                                    *args, **kw)
        # pylint: disable=E0203
        if isinstance(self.id, int):
            self.id = str(self.id)
        # pylint: disable=E0203
        if isinstance(self.service_id, int):
            self.service_id = str(self.service_id)

    @classmethod
    def from_json(cls, json_str, hints=None, model_name=None):
        # Check that fields are valid
        role = json.loads(json_str)
        if model_name is None:
            model_name = "role"
        if model_name in role:
            role = role[model_name]

        invalid = [key for key in role if key not in
                   ['id', 'name', 'description', 'serviceId',
                    # TODO(zns): remove those when we separate grants
                    # from Roles
                    'tenantId', 'userId']]
        if invalid:
            raise fault.BadRequestFault("Invalid attribute(s): %s"
                                        % invalid)

        return super(Role, cls).from_json(json_str, hints=hints,
                                          model_name=model_name)


class Roles(object):
    "A collection of roles."

    def __init__(self, values, links):
        self.values = values
        self.links = links

    def to_xml(self):
        dom = etree.Element("roles")
        dom.set(u"xmlns", "http://docs.openstack.org/identity/api/v2.0")

        for t in self.values:
            dom.append(t.to_dom())

        for t in self.links:
            dom.append(t.to_dom())

        return etree.tostring(dom)

    def to_dom(self):
        dom = etree.Element("roles")
        dom.set(u"xmlns", "http://docs.openstack.org/identity/api/v2.0")

        if self.values:
            for t in self.values:
                dom.append(t.to_dom())

        if self.links:
            for t in self.links:
                dom.append(t.to_dom())

        return dom

    def to_json(self):
        values = [t.to_dict()["role"]
                  for t in self.values]
        links = [t.to_dict()["links"]
                 for t in self.links]
        model_name = "roles"
        return json.dumps({model_name: values,
            ("%s_links" % model_name): links})

    def to_json_values(self):
        values = [t.to_dict()["role"] for t in self.values]
        return values


class Token(Resource):
    """ Token model """
    def __init__(self, id=None, user_id=None, expires=None, tenant_id=None,
            *args, **kw):
        super(Token, self).__init__(id=id, user_id=user_id, expires=expires,
                                    tenant_id=tenant_id, *args, **kw)


class UserRoleAssociation(Resource):
    """ Role Grant model """

    hints = {
        'contract_attributes': ['id', 'role_id', 'user_id', 'tenant_id'],
        'types': [('user_id', basestring), ('tenant_id', basestring)],
        'maps': {'userId': 'user_id', 'roleId': 'role_id',
                'tenantId': 'tenant_id'}
    }

    def __init__(self, user_id=None, role_id=None, tenant_id=None,
                 *args, **kw):
        # pylint: disable=E0203
        super(UserRoleAssociation, self).__init__(user_id=user_id,
                                    role_id=role_id, tenant_id=tenant_id,
                                    *args, **kw)
        if isinstance(self.user_id, int):
            # pylint: disable=E0203
            self.user_id = str(self.user_id)
        if isinstance(self.tenant_id, int):
            self.tenant_id = str(self.tenant_id)

    def to_json(self, hints=None, model_name=None):
        if model_name is None:
            model_name = "role"
        return super(UserRoleAssociation, self).to_json(hints=hints,
                                                        model_name=model_name)

    def to_xml(self, hints=None, model_name=None):
        if model_name is None:
            model_name = "role"
        return super(UserRoleAssociation, self).to_xml(hints=hints,
                                                       model_name=model_name)


class Credentials(Resource):
    # pylint: disable=R0913
    def __init__(self, id=None, user_id=None, tenant_id=None, type=None,
            key=None, secret=None, *args, **kw):
        super(Credentials, self).__init__(id=id, user_id=user_id,
            tenant_id=tenant_id, type=type, key=key, secret=secret, *args,
            **kw)
