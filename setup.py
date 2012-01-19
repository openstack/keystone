import os
import subprocess

from setuptools import setup, find_packages

# If Sphinx is installed on the box running setup.py,
# enable setup.py to build the documentation, otherwise,
# just ignore it
cmdclass = {}
try:
    from sphinx.setup_command import BuildDoc

    class local_BuildDoc(BuildDoc):
        def run(self):
            base_dir = os.path.dirname(os.path.abspath(__file__))
            subprocess.Popen(["python", "generate_autodoc_index.py"],
                             cwd=os.path.join(base_dir, "docs")).communicate()
            for builder in ['html', 'man']:
                self.builder = builder
                self.finalize_options()
                BuildDoc.run(self)
    cmdclass['build_sphinx'] = local_BuildDoc
except:
    # unable to import sphinx, politely skip past...
    pass


setup(name='keystone',
      version='2012.1',
      description="Authentication service for OpenStack",
      license='Apache License (2.0)',
      author='OpenStack, LLC.',
      author_email='openstack@lists.launchpad.net',
      url='http://www.openstack.org',
      packages=find_packages(exclude=['test', 'bin']),
      scripts=['bin/keystone', 'bin/keystone-manage'],
      zip_safe=False,
      cmdclass=cmdclass,
      install_requires=['setuptools'],
      )
