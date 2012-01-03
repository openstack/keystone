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

# pylint: disable=C0103

from lxml import etree


class Link(object):
    """An atom link"""

    def __init__(self, rel, href, link_type=None, hreflang=None, title=None):
        self.rel = rel
        self.href = href
        self.link_type = link_type
        self.hreflang = hreflang
        self.title = title

    def to_dict(self):
        links = {}
        if self.link_type:
            links["link_type"] = self.link_type
        if self.hreflang:
            links["hreflang"] = self.hreflang
        if self.title:
            links["title"] = self.title

        links["rel"] = self.rel
        links["href"] = self.href
        return {'links': links}

    def to_dom(self):
        ATOM_NAMESPACE = "http://www.w3.org/2005/Atom"
        ATOM = "{%s}" % ATOM_NAMESPACE
        NSMAP = {'atom': ATOM_NAMESPACE}
        dom = etree.Element(ATOM + "link", nsmap=NSMAP)
        if self.link_type:
            dom.set("link_type", self.link_type)
        if self.link_type:
            dom.set("hreflang", self.hreflang)
        if self.title:
            dom.set("title", self.title)
        dom.set("rel", self.rel)
        dom.set("href", self.href)
        return dom
