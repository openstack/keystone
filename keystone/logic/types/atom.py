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


class Link(object):
    "An atom link"

    def __init__(self, rel, href, link_type=None, hreflang=None, title=None):
        self.__rel = rel
        self.__href = href
        self.__link_type = link_type
        self.__hreflang = hreflang
        self.__title = title

    @property
    def rel(self):
        return self.__rel

    @property
    def href(self):
        return self.__href

    @property
    def link_type(self):
        return self.__link_type

    @property
    def hreflang(self):
        return self.__hreflang

    @property
    def title(self):
        return self.__title
