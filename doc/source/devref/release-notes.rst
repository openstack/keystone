..
      Copyright 2011-2012 OpenStack Foundation
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

==========================
Working with Release Notes
==========================

The Keystone team uses `reno
<https://docs.openstack.org/developer/reno/usage.html>`_ to generate release
notes. These are important user-facing documents that must be included when a
user or operator facing change is performed, like a bug-fix or a new feature. A
release note should be included in the same patch the work is being performed.
Release notes should be easy to read and maintain; should link back to
appropriate documentation readers may need. The following conventions help the
team ensure all release notes achieve those goals.

Most release notes either describe bug fixes or announce support for new
features, both of which are tracked using Launchpad. When creating a release
note that communicates a bug fix, use the bug number in the name of the note:

.. code-block:: bash

    $ reno new bug-1652012
    Created new notes file in releasenotes/notes/bug-1652012-7c53b9702b10084d.yaml

The body of the release note should clearly explain how the impact will affect
users and operators. It should also include why the change was necessary but
not be overspecific about implementation details, as that can be found in the
commit. It should contain a properly formatted link in reStructuredText that
points back to the original bug report used to track the fix. This makes
reading release notes easier because readers can get a quick summary of the
change, understand how it is going to impact them, and follow a link to more
detail if they choose.

.. code-block:: yaml

    ---
    fixes:
      - |
        [`bug 1652012 <https://bugs.launchpad.net/keystone/+bug/1652012>`_]
        Changes the token_model to return is_admin_project False if the
        attribute is not defined. Returning True for this has the potential to
        be dangerous and the given reason for keeping it True was strictly for
        backwards compatability.

Release notes detailing feature work follow the same basic format, but instead
of using the bug number in the name of the release note, use the blueprint slug
used to track the feature work:

.. code-block:: bash

    $ reno new bp-support-fizzbangs
    Created new notes file in releasenotes/notes/bp-support-fizzbangs-d8f6a3d81c2a465f.yaml

Just like release notes communicating bug fixes, release notes detailing
feature work must contain a link back to the blueprint. Readers should be able
to easily discover all patches that implement the feature, as well as find
links to the full specification and documentation. All of this is typically
found in the blueprint registered in Launchpad.

.. code-block:: yaml

    ---
    features:
      - >
        [`blueprint support-fizzbangs<https://blueprints.launchpad.net/keystone/+spec/support-fizzbangs>`_]
        Keystone now fully supports the usage of fizzbangs.

In the rare case there is a release note that does not pertain to a bug or
feature work, use a sensible slug and include any documentation relating to the
note. We can iterate on the content and application of the release note during
the review process.

For more information on how and when to create release notes, see the
`project-team-guide <https://docs.openstack.org/project-team-guide/release-management.html#how-to-add-new-release-notes>`_.
