# vim: tabstop=4 shiftwidth=4 softtabstop=4

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
    def _tag_name(tag, namespace):
        """Returns a tag name.

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
                prefix = xmlns.get('prefix', None)
                break
        if prefix is not None:
            return '%(PREFIX)s:%(tag_name)s' \
                % {'PREFIX': prefix, 'tag_name': tag_name}
        else:
            return tag_name

    def walk_element(self, element, namespace=False):
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
        decoded_tag = XmlDeserializer._tag_name(element.tag, namespace)
        list_item_tag = None
        if (decoded_tag[-1] == 's' and len(values) == 0 and
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
        for child in [self.walk_element(x) for x in element
                      if not isinstance(x, ENTITY_TYPE)]:
            if list_item_tag:
                # FIXME(gyee): special-case lists for now until we
                # figure out how to properly handle them.
                # If any key ends with an 's', we are assuming it is a list.
                if list_item_tag in child:
                    values.append(child[list_item_tag])
                else:
                    links = child['links']
            else:
                values = dict(values.items() + child.items())

        # set empty and none-list element to None to align with JSON
        if not values:
            values = ""

        d = {XmlDeserializer._tag_name(element.tag, namespace): values}

        if links:
            d['links'] = links
            d['links'].setdefault('next')
            d['links'].setdefault('previous')

        return d


class XmlSerializer(object):
    def __call__(self, d, xmlns=None):
        """Returns an xml etree populated by the given dictionary.

        Optionally, namespace the etree by specifying an ``xmlns``.

        """
        links = None
        # FIXME(dolph): skipping links for now
        for key in d.keys():
            if '_links' in key:
                d.pop(key)
            # FIXME(gyee): special-case links in collections
            if 'links' == key:
                if links:
                    # we have multiple links
                    raise Exception('Multiple links found')
                links = d.pop(key)

        assert len(d.keys()) == 1, ('Cannot encode more than one root '
                                    'element: %s' % d.keys())

        # name the root dom element
        name = d.keys()[0]
        m = re.search('[^:]+$', name)
        root_name = m.string[m.start():]
        prefix = m.string[0:m.start() - 1]
        for ns in XMLNS_LIST:
            if prefix == ns.get('prefix', None):
                xmlns = ns['value']
                break
        # only the root dom element gets an xlmns
        root = etree.Element(root_name, xmlns=(xmlns or XMLNS))

        self.populate_element(root, d[name])

        # FIXME(gyee): special-case links for now
        if links:
            self._populate_links(root, links)

        # TODO(dolph): you can get a doctype from lxml, using ElementTrees
        return '%s\n%s' % (DOCTYPE, etree.tostring(root, pretty_print=True))

    def _populate_links(self, element, links_json):
        links = etree.Element('links')
        for k, v in links_json.iteritems():
            if v:
                link = etree.Element('link')
                link.set('rel', unicode(k))
                link.set('href', unicode(v))
                links.append(link)
        element.append(links)

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

            # NOTE(blk-u): For compatibility with Folsom, when serializing the
            # v2.0 version element also add the links to the base element.
            if (value.get('id') == 'v2.0' and
                    value.get('status') == 'stable' and
                    value.get('updated') == '2013-03-06T00:00:00Z'):

                for item in value['links']:
                    child = etree.Element('link')
                    self.populate_element(child, item)
                    element.append(child)

        elif isinstance(value, basestring):
            element.text = unicode(value)

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
