#!/usr/bin/python
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

from setuptools import setup, find_packages

version = '1.0'

setup(
    name='keystone',
    version=version,
    description="Authentication service - proposed for OpenStack",
    license='Apache License (2.0)',
    classifiers=["Programming Language :: Python"],
    keywords='identity auth authentication openstack',
    author='OpenStack, LLC.',
    author_email='openstack@lists.launchpad.net',
    url='http://www.openstack.org',
    include_package_data=True,
    packages=find_packages(exclude=['test', 'bin']),
    scripts=['bin/keystone', 'bin/keystone-auth', 'bin/keystone-admin',
             'bin/keystone-manage'],
    zip_safe=False,
    install_requires=['setuptools'],
    entry_points={
        'paste.app_factory': ['main=identity:app_factory'],
        'paste.filter_factory': [
            'remoteauth=keystone.middleware.remoteauth:remoteauth_factory',
            'tokenauth=keystone.auth_protocols.auth_token:filter_factory',
            ],
        },
    )
