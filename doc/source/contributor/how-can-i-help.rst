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

Are you interested in contributing to the keystone project? Whether you're a
software developer, a technical writer, an OpenStack operator or an OpenStack
user, there are many reasons to get involved with the keystone project:

* You can help shape the direction of the project, ensuring it meets your
  organization's needs in the future
* You can help maintain the project's health and get your bugs fixed faster
* You can collaborate with other people to find common solutions that will help
  you and your organization
* You can hack on a fun, security-related Python project with interesting
  challenges

Here are some easy ways to make a big difference to the keystone project and
become part of the team:

* Read the documentation, starting with the rest of this contributor guide, and
  try to follow it to set up keystone and try out different features. Does it
  make sense? Is something out of date? Is something misleading or incorrect?
  Submit a patch or bug report to fix it.
* Monitor incoming bug reports, try to reproduce the bug in a test environment,
  ask the bug reporter for more information, answer support questions and close
  invalid bugs. Follow the `bug triage guide`_. New bugs can be found with the
  "New" status:

  * `keystone <https://bugs.launchpad.net/keystone/+bugs?field.status=New>`__
  * `keystonemiddleware <https://bugs.launchpad.net/keystonemiddleware/+bugs?field.status=New>`__
  * `keystoneauth <https://bugs.launchpad.net/keystoneauth/+bugs?field.status=New>`__
  * `python-keystoneclient <https://bugs.launchpad.net/python-keystoneclient/+bugs?field.status=New>`__

  You can also subscribe to email notifications for new bugs.
* Subscribe to the openstack-discuss@lists.openstack.org mailing list (filter on
  subject tag ``[keystone]``) and join the #openstack-keystone IRC channel on
  OFTC. Help answer user support questions if you or your organization has
  faced and solved a similar problem, or chime in on design discussions that
  will affect you and your organization.
* Check out the low hanging fruit bugs, submit patches to fix them:

  * `keystone <https://bugs.launchpad.net/keystone/+bugs?field.tag=low-hanging-fruit>`__
  * `keystonemiddleware <https://bugs.launchpad.net/keystonemiddleware/+bugs?field.tag=low-hanging-fruit>`__
  * `keystoneauth <https://bugs.launchpad.net/keystoneauth/+bugs?field.tag=low-hanging-fruit>`__
  * `python-keystoneclient <https://bugs.launchpad.net/python-keystoneclient/+bugs?field.tag=low-hanging-fruit>`__

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

Need any help? :doc:`Reach out </getting-started/community>` to the keystone team.

.. _bug triage guide: https://wiki.openstack.org/wiki/BugTriage
.. _devstack: https://docs.openstack.org/devstack/latest/
.. _keystone maintainers: https://review.opendev.org/#/admin/groups/9,members
.. _new changes: https://review.opendev.org/#/q/is:open+project:openstack/keystone+OR+project:openstack/keystonemiddleware+OR+project:openstack/keystoneauth+OR+project:openstack/python-keystoneclient
.. _review guidelines: https://docs.openstack.org/project-team-guide/review-the-openstack-way.html

The Meaning of Low Hanging Fruit
================================

This section describes the intent behind bugs tagged as low hanging fruit.
Current maintainers should apply the tag consistently while triaging bugs,
using this document as a guide. This practice ensures newcomers to the project
can expect each low hanging fruit bug to be of similar complexity.

Bugs fit for the low hanging fruit tag:

* Should require minimal python experience, someone new to OpenStack might also
  be new to python
* Should only require a basic understanding of the review workflow, complicated
  changesets with dependencies between repositories coupled with CI testing
  only raises the cognitive bar for new contributors
* Can include documentation fixes so long it doesn't require an
  in-depth understanding of complicated subsystems and features (e.g.,
  overhauling the federated identity guide)
* Should be something a newcomer can progress through in a week or less, long
  wait times due to the discussion of complicated topics can deter new
  contributors from participating
* Shouldn't require a new contributor to understand copious amounts of
  historical context, newcomers should eventually understand this information
  but consuming that information is outside the scope of low hanging fruit
