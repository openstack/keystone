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

from keystone import version
import os
import subprocess
import sys

from setuptools import setup, find_packages

cmdclass = {}

# If Sphinx is installed on the box running setup.py,
# enable setup.py to build the documentation, otherwise,
# just ignore it
try:
    from sphinx.setup_command import BuildDoc

    class local_BuildDoc(BuildDoc):
        def run(self):
            base_dir = os.path.dirname(os.path.abspath(__file__))
            subprocess.Popen(["python", "generate_autodoc_index.py"],
                             cwd=os.path.join(base_dir, "doc")).communicate()
            for builder in ['html', 'man']:
                self.builder = builder
                self.finalize_options()
                BuildDoc.run(self)
    cmdclass['build_sphinx'] = local_BuildDoc

except:
    pass

setup(
    name='keystone',
    version=version.canonical_version(),
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
             'bin/keystone-manage', 'bin/keystone-import',
             'bin/keystone-control'],
    zip_safe=False,
    cmdclass=cmdclass,
    tests_require=['nose', 'unittest2', 'webtest', 'mox', 'pylint', 'pep8'],
    test_suite='keystone.test.runtests',
    entry_points={
        'paste.app_factory': ['main=identity:app_factory'],
        'paste.filter_factory': [
            'extfilter=keystone.middleware.url:filter_factory',
            'remoteauth=keystone.middleware.remoteauth:remoteauth_factory',
            'tokenauth=keystone.middleware.auth_token:filter_factory',
            'swiftauth=keystone.middleware.swift_auth:filter_factory',
            's3token=keystone.middleware.s3_token:filter_factory',
            ],
        },
    )
