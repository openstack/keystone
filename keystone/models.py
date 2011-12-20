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
            format is a list of attribute names(ex ['description'])
"""

import json

from lxml import etree

from keystone.utils import fault


class Resource(dict):
    """ Base class for models

    Provides basic functionality that can be overridden """

    def __init__(self, *args, **kw):
        """ Initialize object
        kwargs contain static properties
        """
        super(Resource, self).__init__(*args, **kw)
        # attributes that can be used as attributes. Example:
        #    tenant.id  - here id is a contract attribute
        # initialize dynamically (to prevent recursion on __setattr__)
        super(Resource, self).__setattr__("contract_attributes", [])
        # set statically for references
        self.contract_attributes = []

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
            raise AttributeError("'%s' not found on object of class '%s'" % \
                                 (name, self.__class__.__name__))

    def __setattr__(self, name, value):
        """ Supports setting contract attributes (ex. tenant.name = 'A1')

        This should only be called if the original call did not match
        an attribute (Python's rules)."""
        if name in self.contract_attributes:
            if value is not None:
                self[name] = value
        elif name == 'contract_attributes':
            # Allow someone to set that
            super(Resource, self).__setattr__(name, value)
        else:
            raise AttributeError("'%s' not found on object of class '%s'" % \
                                 (name, self.__class__.__name__))

    def __getitem__(self, name):
        if name in self.contract_attributes:
            if super(Resource, self).__contains__(name):
                return super(Resource, self).__getitem__(name)
            return None
        elif name == 'desc':  # TODO(zns): deprecate thise
            # We need to maintain this compatibility with this nasty attribute
            # until we're done refactoring
            return self.description
        else:
            return super(Resource, self).__getitem__(name)

    def __setitem__(self, name, value):
        super(Resource, self).__setitem__(name, value)

    def __contains__(self, key):
        if key in self.contract_attributes:
            return True
        return super(Resource, self).__contains__(key)

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
        return errors is None

    # pylint: disable=W0613, R0201
    def inspect(self, fail_fast=None):
        """ Validates and retuns validation results without raising any errors
        :param fail_fast" return after first validation failure

        :returns: [(faultClass, message), ...], ordered by relevance
            - if None, then no errors found
        """
        return None

    #
    # Serialization Functions - may be moved to a different class
    #
    def __str__(self):
        return str(self.to_dict())

    def to_dict(self):
        """ For compatibility with logic.types """
        root_name = self.__class__.__name__.lower()
        return {root_name: self.strip_null_fields(self.copy())}

    @staticmethod
    def strip_null_fields(dict_object):
        """ Strips null fields from dict"""
        for k, v in dict_object.items():
            if v is None:
                del dict_object[k]
        return dict_object

    @staticmethod
    def write_dict_to_xml(dict_object, xml, tags=None):
        """ Attempts to convert a dict into XML as best as possible.
        Converts named keys and attributes and recursively calls for
        any values are are embedded dicts

        :param tags: accepts a list of attribute names that should go into XML
        tags instead of attributes
        """
        if tags is None:
            tags = []
        for name, value in dict_object.iteritems():
            if isinstance(value, dict):
                element = etree.SubElement(xml, name)
                Resource.write_dict_to_xml(value, element)
            elif name in tags:
                element = xml.find(name)
                if element is None:
                    element = etree.SubElement(xml, name)
                if isinstance(value, dict):
                    Resource.write_dict_to_xml(value, element)
                else:
                    if value:
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

    def apply_type_mappings(self, type_mappings):
        """ Applies type mappings to dict values
        Right now only handles integer mappings"""
        if type_mappings:
            for name, type in type_mappings:
                if type is int:
                    self[name] = int(self[name])
                elif type is str:
                    # Move sub to string
                    if name in self and self[name] is dict:
                        self[name] = self[name][0]
                else:
                    raise NotImplementedError("Model type mappings cannot \
                                handle '%s' types" % type.__class__.__name__)

    def to_json(self, hints=None):
        """ Serializes object to json - implies latest Keystone contract """
        d = self.to_dict()
        if hints:
            if "types" in hints:
                Resource.apply_type_mappings(d, hints["types"])
        return json.dumps(d)

    def to_xml(self, hints=None):
        """ Serializes object to XML string
            - implies latest Keystone contract
            :param hints: see introduction on format"""
        tags = None
        if hints:
            if 'tags' in hints:
                tags = hints['tags']

        dom = self.to_dom(tags=tags)
        Resource.write_dict_to_xml(self, dom, tags=tags)
        return etree.tostring(dom)

    def to_dom(self, xmlns=None, tags=None):
        """ Serializes object to XML objec
        - implies latest Keystone contract
        :param xmlns: accepts an optional namespace for XML
        :param tags: accepts a list of attribute names that should go into XML
        tags instead of attributes
        """
        if tags is None:
            tags = []
        if xmlns:
            dom = etree.Element(self.__class__.__name__.lower(), xmlns=xmlns)
        else:
            dom = etree.Element(self.__class__.__name__.lower())
        Resource.write_dict_to_xml(self, dom, tags)
        return dom

    @classmethod
    def from_json(cls, json_str, hints=None):
        """ Deserializes object from json - assumes latest Keystone
        contract
        """
        try:
            object = json.loads(json_str)

            model_name = cls.__name__.lower()
            if model_name in object:
                # Ignore class name if it is there
                object = object[model_name]

            model_object = None
            type_mappings = None
            if hints:
                if 'types' in hints:
                    type_mappings = hints['types']
                if 'contract_attributes' in hints:
                    # build mapping and instantiate object with
                    # contract_attributes provided
                    params = {}
                    for name in hints['contract_attributes']:
                        if name in object:
                            params[name] = object[name]
                        else:
                            params[name] = None
                    model_object = cls(**params)
            if model_object is None:
                model_object = cls()
            model_object.update(object)
            if type_mappings:
                model_object.apply_type_mappings(type_mappings)
            return model_object
        except (ValueError, TypeError) as e:
            raise fault.BadRequestFault("Cannot parse '%s' json" % \
                                        cls.__name__, str(e))

    @classmethod
    def from_xml(cls, xml_str, hints=None):
        """ Deserializes object from XML - assumes latest Keystone
        contract """
        try:
            object = etree.fromstring(xml_str)
            model_object = None
            type_mappings = None
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
            if model_object is None:
                model_object = cls()
            cls.write_xml_to_dict(object, model_object)
            if type_mappings:
                model_object.apply_type_mappings(type_mappings)
            return model_object
        except etree.LxmlError as e:
            raise fault.BadRequestFault("Cannot parse '%s' xml" % cls.__name__,
                                        str(e))

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
    def __init__(self, id=None, type=None, name=None, description=None,
                 *args, **kw):
        super(Service, self).__init__(id=id, type=type, name=name,
                                      description=description, *args, **kw)

    def to_json_20(self):
        return super(Service, self).to_json_20()

    def inspect(self, fail_fast=None):
        result = super(Service, self).inspect(fail_fast)
        if fail_fast and result:
            return result


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

    def to_dom(self, xmlns=None, tags=None):
        if tags is None:
            tags = ["description"]
        if xmlns is None:
            xmlns = "http://docs.openstack.org/identity/api/v2.0"

        return super(Tenant, self).to_dom(xmlns=xmlns, tags=tags)

    def to_xml(self, hints=None):
        if hints is None:
            hints = {}
        if 'tags' not in hints:
            hints['tags'] = ["description"]
        return super(Tenant, self).to_xml(hints=hints)

    def to_json(self, hints=None):
        if hints is None:
            hints = {}
        return super(Tenant, self).to_json(hints=hints)


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


class EndpointTemplate(Resource):
    """ EndpointTemplate model """
    # pylint: disable=R0913
    def __init__(self, id=None, region=None, name=None, type=None,
                 public_url=None, admin_url=None,
                 internal_url=None, enabled=None, is_global=None,
                 version_id=None, version_list=None, version_info=None,
                 *args, **kw):
        super(EndpointTemplate, self).__init__(id=id, region=region, name=name,
                 type=type, public_url=public_url, admin_url=admin_url,
                 internal_url=internal_url, enabled=enabled,
                 is_global=is_global, version_id=version_id,
                 version_list=version_list, version_info=version_info,
                                      *args, **kw)


class Endpoint(Resource):
    """ Endpoint model """
    # pylint: disable=R0913
    def __init__(self, id=None, tenant_id=None, region=None, name=None,
                 type=None, public_url=None, admin_url=None,
                 internal_url=None, version_id=None, version_list=None,
                 version_info=None,
                 *args, **kw):
        super(Endpoint, self).__init__(id=id, tenant_id=tenant_id,
                 region=region, name=name, type=type, public_url=public_url,
                 admin_url=admin_url, internal_url=internal_url,
                 version_id=version_id, version_list=version_list,
                 version_info=version_info,
                                      *args, **kw)


class Role(Resource):
    """ Role model """
    def __init__(self, id=None, name=None, description=None, service_id=None,
                 tenant_id=None, *args, **kw):
        super(Role, self).__init__(id=id, name=name, description=description,
                                   service_id=service_id, tenant_id=tenant_id,
                                    *args, **kw)


class Token(Resource):
    """ Token model """
    def __init__(self, id=None, user_id=None, expires=None, tenant_id=None,
            *args, **kw):
        super(Token, self).__init__(id=id, user_id=user_id, expires=expires,
                                    tenant_id=tenant_id, *args, **kw)


class UserRoleAssociation(Resource):
    """ Role Grant model """
    def __init__(self, user_id=None, role_id=None, tenant_id=None,
                 *args, **kw):
        super(UserRoleAssociation, self).__init__(user_id=user_id,
                                    role_id=role_id, tenant_id=tenant_id,
                                    *args, **kw)


class Credentials(Resource):
    # pylint: disable=R0913
    def __init__(self, id=None, user_id=None, tenant_id=None, type=None,
            key=None, secret=None, *args, **kw):
        super(Credentials, self).__init__(id=id, user_id=user_id,
            tenant_id=tenant_id, type=type, key=key, secret=secret, *args,
            **kw)
