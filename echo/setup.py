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
    name='echo',
    version=version,
    description="",
    license='Apache License (2.0)',
    classifiers=["Programming Language :: Python"],
    keywords='',
    author='OpenStack, LLC.',
    include_package_data=True,
    packages=find_packages(exclude=['test', 'bin']),
    zip_safe=False,
    install_requires=['setuptools', 'keystone'],
    entry_points={
        'paste.app_factory': ['main=echo:app_factory'],
        'paste.filter_factory': [
            'papiauth=keystone:papiauth_factory',
            ],
        },
    )
