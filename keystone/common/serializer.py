# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2012 OpenStack LLC
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


DOCTYPE = '<?xml version="1.0" encoding="UTF-8"?>'
XMLNS = 'http://docs.openstack.org/identity/api/v2.0'


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
        dom = etree.fromstring(xml_str.strip())
        return self.walk_element(dom)

    @staticmethod
    def _tag_name(tag):
        """Remove the namespace from the tagname.

        TODO(dolph): We might care about the namespace at some point.

        >>> XmlDeserializer._tag_name('{xmlNamespace}tagName')
        'tagName'

        """
        m = re.search('[^}]+$', tag)
        return m.string[m.start():]

    def walk_element(self, element):
        """Populates a dictionary by walking an etree element."""
        values = {}
        for k, v in element.attrib.iteritems():
            # boolean-looking attributes become booleans in JSON
            if k in ['enabled']:
                if v in ['true']:
                    v = True
                elif v in ['false']:
                    v = False

            values[k] = v

        text = None
        if element.text is not None:
            text = element.text.strip()

        # current spec does not have attributes on an element with text
        values = values or text or {}

        for child in [self.walk_element(x) for x in element]:
            values = dict(values.items() + child.items())

        return {XmlDeserializer._tag_name(element.tag): values}


class XmlSerializer(object):
    def __call__(self, d, xmlns=None):
        """Returns an xml etree populated by the given dictionary.

        Optionally, namespace the etree by specifying an ``xmlns``.

        """
        # FIXME(dolph): skipping links for now
        for key in d.keys():
            if '_links' in key:
                d.pop(key)

        assert len(d.keys()) == 1, ('Cannot encode more than one root '
            'element: %s' % d.keys())

        # name the root dom element
        name = d.keys()[0]

        # only the root dom element gets an xlmns
        root = etree.Element(name, xmlns=(xmlns or XMLNS))

        self.populate_element(root, d[name])

        # TODO(dolph): you can get a doctype from lxml, using ElementTrees
        return '%s\n%s' % (DOCTYPE, etree.tostring(root, pretty_print=True))

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
        elif k == 'serviceCatalog':
            # xsd compliance: <serviceCatalog> contains <service>s
            container = etree.Element(k)
            element.append(container)
            name = 'service'
        elif k == 'values' and element.tag[-1] == 's':
            # OS convention is to contain lists in a 'values' element,
            # so the list itself can have attributes, which is
            # unnecessary in XML
            name = element.tag[:-1]
        elif k[-1] == 's':
            name = k[:-1]
        else:
            name = k

        for item in v:
            child = etree.Element(name)
            self.populate_element(child, item)
            container.append(child)

    def _populate_dict(self, element, k, v):
        """Populates an element with a key & dictionary value."""
        child = etree.Element(k)
        self.populate_element(child, v)
        element.append(child)

    def _populate_bool(self, element, k, v):
        """Populates an element with a key & boolean value."""
        # booleans are 'true' and 'false'
        element.set(k, unicode(v).lower())

    def _populate_str(self, element, k, v):
        """Populates an element with a key & string value."""
        if k in ['description']:
            # always becomes an element
            child = etree.Element(k)
            child.text = unicode(v)
            element.append(child)
        else:
            # add attributes to the current element
            element.set(k, unicode(v))

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

    def _populate_sequence(self, element, l):
        """Populates an etree with a sequence of elements, given a list."""
        # xsd compliance: child elements are singular: <users> has <user>s
        name = element.tag
        if element.tag[-1] == 's':
            name = element.tag[:-1]

        for item in l:
            child = etree.Element(name)
            self.populate_element(child, item)
            element.append(child)

    def _populate_tree(self, element, d):
        """Populates an etree with attributes & elements, given a dict."""
        for k, v in d.iteritems():
            if isinstance(v, dict):
                self._populate_dict(element, k, v)
            elif isinstance(v, list):
                self._populate_list(element, k, v)
            elif isinstance(v, bool):
                self._populate_bool(element, k, v)
            elif isinstance(v, basestring):
                self._populate_str(element, k, v)
            elif type(v) in [int, float, long, complex]:
                self._populate_number(element, k, v)
