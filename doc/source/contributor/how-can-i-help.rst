..
      Copyright 2018 SUSE Linux GmbH
      All Rights Reserved.

      Licensed under the Apache License, Version 2.0 (the "License"); you may
      not use this file except in compliance with the License. You may obtain
      a copy of the License at

          http://www.apache.org/licenses/LICENSE-2.0

      Unless required by applicable law or agreed to in writing, software
      distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
      WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
      License for the specific language governing permissions and limitations
      under the License.

===============
How Can I Help?
===============

Are you new to OpenStack or keystone? Are you interested in contributing, but
not sure where to start? Here are some easy ways that you can make a difference
while you learn the ropes:

* Read the documentation, starting with the rest of this contributor guide, and
  try to follow it to set up keystone and try out different features. Does it
  make sense? Is something out of date? Is something misleading or incorrect?
  Submit a patch to fix it.
* Check out the low hanging fruit bugs:

  * `keystone`_
  * `keystonemiddleware`_
  * `keystoneauth`_
  * `python-keystoneclient`_

* Look for deprecation warnings in the unit tests and in the keystone logs of a
  running keystone installation and submit patches to make them go away.
* Look at other projects, especially `devstack`_, and submit patches to correct
  usage of options that keystone has deprecated. Make sure to let the `keystone
  maintainers`_ know you're looking at these so that it's on their radar and
  they can help review.
* Check the test coverage report (``tox -ecover``) and try to add unit test
  coverage.
* Review `new changes`_. Keep OpenStack's `review guidelines`_ in mind. Ask
  questions when you don't understand a change.

Need any help? `Reach out`_ to the keystone team.

.. _keystone: https://bugs.launchpad.net/keystone/+bugs?field.tag=low-hanging-fruit
.. _keystonemiddleware: https://bugs.launchpad.net/keystonemiddleware/+bugs?field.tag=low-hanging-fruit
.. _keystoneauth: https://bugs.launchpad.net/keystoneauth/+bugs?field.tag=low-hanging-fruit
.. _python-keystoneclient: https://bugs.launchpad.net/python-keystoneclient/+bugs?field.tag=low-hanging-fruit
.. _devstack: https://docs.openstack.org/devstack/latest/
.. _keystone maintainers: https://review.openstack.org/#/admin/groups/9,members
.. _new changes: https://review.openstack.org/#/q/is:open+project:openstack/keystone+OR+project:openstack/keystonemiddleware+OR+project:openstack/keystoneauth+OR+project:openstack/python-keystoneclient
.. _review guidelines: https://docs.openstack.org/project-team-guide/review-the-openstack-way.html
.. _Reach out: ../getting-started/community.html
