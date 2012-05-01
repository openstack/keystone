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

from setuptools import find_packages
from setuptools.command.sdist import sdist
from setuptools import setup
import subprocess

from keystone.openstack.common.setup import generate_authors
from keystone.openstack.common.setup import parse_requirements
from keystone.openstack.common.setup import parse_dependency_links
from keystone.openstack.common.setup import write_requirements
from keystone.openstack.common.setup import write_git_changelog


class local_sdist(sdist):
    """Customized sdist hook - builds the ChangeLog file from VC first"""
    def run(self):
        write_git_changelog()
        generate_authors()
        sdist.run(self)
cmdclass = {'sdist': local_sdist}


try:
    from sphinx.setup_command import BuildDoc

    class local_BuildDoc(BuildDoc):
        def run(self):
            subprocess.call('sphinx-apidoc -f -o doc/source keystone',
                            shell=True)
            for builder in ['html', 'man']:
                self.builder = builder
                self.finalize_options()
                BuildDoc.run(self)
    cmdclass['build_sphinx'] = local_BuildDoc

except:
    pass


requires = parse_requirements()
depend_links = parse_dependency_links()

write_requirements()

setup(name='keystone',
      version='2012.2',
      description="Authentication service for OpenStack",
      license='Apache License (2.0)',
      author='OpenStack, LLC.',
      author_email='openstack@lists.launchpad.net',
      url='http://www.openstack.org',
      cmdclass=cmdclass,
      packages=find_packages(exclude=['test', 'bin']),
      include_package_data=True,
      scripts=['bin/keystone-all', 'bin/keystone-manage'],
      zip_safe=False,
      install_requires=requires,
      dependency_links=depend_links,
      test_suite='nose.collector',
      )
