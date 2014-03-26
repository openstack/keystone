# Copyright 2012 OpenStack Foundation
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

"""
Dict <--> XML de/serializer.

The identity API prefers attributes over elements, so we serialize that way
by convention, with a few hardcoded exceptions.

"""

from lxml import etree
import re

import six

from keystone.openstack.common.gettextutils import _


DOCTYPE = '<?xml version="1.0" encoding="UTF-8"?>'
XMLNS = 'http://docs.openstack.org/identity/api/v2.0'
XMLNS_LIST = [
    {
        'value': 'http://docs.openstack.org/identity/api/v2.0'
    },
    {
        'prefix': 'OS-KSADM',
        'value': 'http://docs.openstack.org/identity/api/ext/OS-KSADM/v1.0',
    },
]

PARSER = etree.XMLParser(
    resolve_entities=False,
    remove_comments=True,
    remove_pis=True)

# NOTE(dolph): lxml.etree.Entity() is just a callable that currently returns an
# lxml.etree._Entity instance, which doesn't appear to be part of the
# public API, so we discover the type dynamically to be safe
ENTITY_TYPE = type(etree.Entity('x'))


def from_xml(xml):
    """Deserialize XML to a dictionary."""
    if xml is None:
        return None

    deserializer = XmlDeserializer()
    return deserializer(xml)


def to_xml(d, xmlns=None):
    """Serialize a dictionary to XML."""
    if d is None:
        return None

    serialize = XmlSerializer()
    return serialize(d, xmlns)


class XmlDeserializer(object):
    def __call__(self, xml_str):
        """Returns a dictionary populated by decoding the given xml string."""
        dom = etree.fromstring(xml_str.strip(), PARSER)
        return self.walk_element(dom, True)

    def _deserialize_links(self, links):
        return dict((x.attrib['rel'], x.attrib['href']) for x in links)

    @staticmethod
    def _qualified_name(tag, namespace):
        """Returns a qualified tag name.

        The tag name may contain the namespace prefix or not, which can
        be determined by specifying the parameter namespace.

        """
        m = re.search('[^}]+$', tag)
        tag_name = m.string[m.start():]
        if not namespace:
            return tag_name
        bracket = re.search('[^{]+$', tag)
        ns = m.string[bracket.start():m.start() - 1]
        #If the namespace is
        #http://docs.openstack.org/identity/api/ext/OS-KSADM/v1.0
        #for the root element, a prefix needs to add in front of the tag name.
        prefix = None
        for xmlns in XMLNS_LIST:
            if xmlns['value'] == ns:
                prefix = xmlns.get('prefix')
                break
        if prefix is not None:
            return '%(PREFIX)s:%(tag_name)s' \
                % {'PREFIX': prefix, 'tag_name': tag_name}
        else:
            return tag_name

    def walk_element(self, element, namespace=False):
        """Populates a dictionary by walking an etree element."""
        values = {}
        for k, v in six.iteritems(element.attrib):
            # boolean-looking attributes become booleans in JSON
            if k in ['enabled', 'truncated']:
                if v in ['true']:
                    v = True
                elif v in ['false']:
                    v = False

            values[self._qualified_name(k, namespace)] = v

        text = None
        if element.text is not None:
            text = element.text.strip()

        # current spec does not have attributes on an element with text
        values = values or text or {}
        decoded_tag = XmlDeserializer._qualified_name(element.tag, namespace)
        list_item_tag = None
        if (decoded_tag[-1] == 's' and not values and
                decoded_tag != 'access'):
            # FIXME(gyee): special-case lists for now unti we
            # figure out how to properly handle them.
            # If any key ends with an 's', we are assuming it is a list.
            # List element have no attributes.
            values = list(values)
            if decoded_tag == 'policies':
                list_item_tag = 'policy'
            else:
                list_item_tag = decoded_tag[:-1]

        if decoded_tag == 'links':
            return {'links': self._deserialize_links(element)}

        links = None
        truncated = False
        for child in [self.walk_element(x) for x in element
                      if not isinstance(x, ENTITY_TYPE)]:
            if list_item_tag:
                # FIXME(gyee): special-case lists for now until we
                # figure out how to properly handle them.
                # If any key ends with an 's', we are assuming it is a list.
                if list_item_tag in child:
                    values.append(child[list_item_tag])
                else:
                    if 'links' in child:
                        links = child['links']
                    else:
                        truncated = child['truncated']
            else:
                values = dict(values.items() + child.items())

        # set empty and none-list element to None to align with JSON
        if not values:
            values = ""

        d = {XmlDeserializer._qualified_name(element.tag, namespace): values}

        if links:
            d['links'] = links
            d['links'].setdefault('next')
            d['links'].setdefault('previous')

        if truncated:
            d['truncated'] = truncated['truncated']

        return d


class XmlSerializer(object):
    def __call__(self, d, xmlns=None):
        """Returns an xml etree populated by the given dictionary.

        Optionally, namespace the etree by specifying an ``xmlns``.

        """
        links = None
        truncated = False
        # FIXME(dolph): skipping links for now
        for key in d.keys():
            if '_links' in key:
                d.pop(key)
            # NOTE(gyee, henry-nash): special-case links and truncation
            # attribute in collections
            if 'links' == key:
                if links:
                    # we have multiple links
                    raise Exception('Multiple links found')
                links = d.pop(key)
            if 'truncated' == key:
                if truncated:
                    # we have multiple attributes
                    raise Exception(_('Multiple truncation attributes found'))
                truncated = d.pop(key)
        assert len(d.keys()) == 1, ('Cannot encode more than one root '
                                    'element: %s' % d.keys())

        # name the root dom element
        name = d.keys()[0]
        m = re.search('[^:]+$', name)
        root_name = m.string[m.start():]
        prefix = m.string[0:m.start() - 1]
        for ns in XMLNS_LIST:
            if prefix == ns.get('prefix'):
                xmlns = ns['value']
                break
        # only the root dom element gets an xlmns
        root = etree.Element(root_name, xmlns=(xmlns or XMLNS))

        self.populate_element(root, d[name])

        # NOTE(gyee, henry-nash): special-case links and truncation attribute
        if links:
            self._populate_links(root, links)
        if truncated:
            self._populate_truncated(root, truncated)

        # TODO(dolph): you can get a doctype from lxml, using ElementTrees
        return '%s\n%s' % (DOCTYPE, etree.tostring(root, pretty_print=True))

    def _populate_links(self, element, links_json):
        links = etree.Element('links')
        for k, v in six.iteritems(links_json):
            if v:
                link = etree.Element('link')
                link.set('rel', six.text_type(k))
                link.set('href', six.text_type(v))
                links.append(link)
        element.append(links)

    def _populate_truncated(self, element, truncated_value):
        truncated = etree.Element('truncated')
        self._populate_bool(truncated, 'truncated', truncated_value)
        element.append(truncated)

    def _populate_list(self, element, k, v):
        """Populates an element with a key & list value."""
        # spec has a lot of inconsistency here!
        container = element

        if k == 'media-types':
            # xsd compliance: <media-types> contains <media-type>s
            # find an existing <media-types> element or make one
            container = element.find('media-types')
            if container is None:
                container = etree.Element(k)
                element.append(container)
            name = k[:-1]
        elif k == 'serviceCatalog' or k == 'catalog':
            # xsd compliance: <serviceCatalog> contains <service>s
            container = etree.Element(k)
            element.append(container)
            name = 'service'
        elif k == 'roles' and element.tag == 'user':
            name = 'role'
        elif k == 'endpoints' and element.tag == 'service':
            name = 'endpoint'
        elif k == 'values' and element.tag[-1] == 's':
            # OS convention is to contain lists in a 'values' element,
            # so the list itself can have attributes, which is
            # unnecessary in XML
            name = element.tag[:-1]
        elif k[-1] == 's':
            container = etree.Element(k)
            element.append(container)
            if k == 'policies':
                # need to special-case policies since policie is not a word
                name = 'policy'
            else:
                name = k[:-1]
        else:
            name = k

        for item in v:
            child = etree.Element(name)
            self.populate_element(child, item)
            container.append(child)

    def _populate_dict(self, element, k, v):
        """Populates an element with a key & dictionary value."""
        if k == 'links':
            # links is a special dict
            self._populate_links(element, v)
        else:
            child = etree.Element(k)
            self.populate_element(child, v)
            element.append(child)

    def _populate_bool(self, element, k, v):
        """Populates an element with a key & boolean value."""
        # booleans are 'true' and 'false'
        element.set(k, six.text_type(v).lower())

    def _populate_str(self, element, k, v):
        """Populates an element with a key & string value."""
        if k in ['description']:
            # always becomes an element
            child = etree.Element(k)
            child.text = six.text_type(v)
            element.append(child)
        else:
            # add attributes to the current element
            element.set(k, six.text_type(v))

    def _populate_number(self, element, k, v):
        """Populates an element with a key & numeric value."""
        # numbers can be handled as strings
        self._populate_str(element, k, v)

    def populate_element(self, element, value):
        """Populates an etree with the given value."""
        if isinstance(value, list):
            self._populate_sequence(element, value)
        elif isinstance(value, dict):
            self._populate_tree(element, value)

            # NOTE(blk-u): For compatibility with Folsom, when serializing the
            # v2.0 version element also add the links to the base element.
            if value.get('id') == 'v2.0':
                for item in value['links']:
                    child = etree.Element('link')
                    self.populate_element(child, item)
                    element.append(child)

        elif isinstance(value, six.string_types):
            element.text = six.text_type(value)

    def _populate_sequence(self, element, l):
        """Populates an etree with a sequence of elements, given a list."""
        # xsd compliance: child elements are singular: <users> has <user>s
        name = element.tag
        if element.tag[-1] == 's':
            name = element.tag[:-1]
            if name == 'policie':
                name = 'policy'

        for item in l:
            child = etree.Element(name)
            self.populate_element(child, item)
            element.append(child)

    def _populate_tree(self, element, d):
        """Populates an etree with attributes & elements, given a dict."""
        for k, v in six.iteritems(d):
            if isinstance(v, dict):
                self._populate_dict(element, k, v)
            elif isinstance(v, list):
                self._populate_list(element, k, v)
            elif isinstance(v, bool):
                self._populate_bool(element, k, v)
            elif isinstance(v, six.string_types):
                self._populate_str(element, k, v)
            elif type(v) in [int, float, long, complex]:
                self._populate_number(element, k, v)
