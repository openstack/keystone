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

import setuptools

from keystone.openstack.common import setup


requires = setup.parse_requirements()
depend_links = setup.parse_dependency_links()
project = 'keystone'


setuptools.setup(
    name=project,
    version=setup.get_version(project, '2013.1'),
    description="Authentication service for OpenStack",
    license='Apache License (2.0)',
    author='OpenStack, LLC.',
    author_email='openstack@lists.launchpad.net',
    url='http://www.openstack.org',
    cmdclass=setup.get_cmdclass(),
    packages=setuptools.find_packages(exclude=['test', 'bin']),
    include_package_data=True,
    scripts=['bin/keystone-all', 'bin/keystone-manage'],
    zip_safe=False,
    install_requires=requires,
    dependency_links=depend_links,
    test_suite='nose.collector',
    classifiers=[
        'Environment :: OpenStack',
        'Intended Audience :: Information Technology',
        'Intended Audience :: System Administrators',
        'License :: OSI Approved :: Apache Software License',
        'Operating System :: POSIX :: Linux',
        'Programming Language :: Python',
        'Programming Language :: Python :: 2',
        'Programming Language :: Python :: 2.7',
    ],
)
