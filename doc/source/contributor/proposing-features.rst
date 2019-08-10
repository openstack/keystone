..
      Licensed under the Apache License, Version 2.0 (the "License"); you may
      not use this file except in compliance with the License. You may obtain
      a copy of the License at

          http://www.apache.org/licenses/LICENSE-2.0

      Unless required by applicable law or agreed to in writing, software
      distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
      WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
      License for the specific language governing permissions and limitations
      under the License.

.. _proposing_features:

==================
Proposing Features
==================

Requests for enhancements or new features must follow a process that requires
using bug reports and specifications. We publish the contents of the
`keystone-specs repository
<https://opendev.org/openstack/keystone-specs>`_ at
`specs.openstack.org <https://specs.openstack.org/openstack/keystone-specs/>`_.

RFE Bug Reports
===============

All code, documentation, and tests implementing a feature should be tracked.
To do this, we use Launchpad bug reports. We use bug reports because the
OpenStack review infrastructure has existing tooling that groups patches based
on commit message syntax. When you propose a patch that is related to a bug or
a feature, the OpenStack Infrastructure bot automatically links the patch as a
comment in the bug report. Comments are also immutable, allowing us to track
long-running initiatives without losing context.

To create an RFE bug report, file a bug against the appropriate project. For
example, if we were to create an RFE bug report for supporting a new Foobar API
within keystone, we'd `open <https://bugs.launchpad.net/keystone/+filebug>`_
that RFE against the keystone project. The title should start with "RFE: ",
followed by a snippet of the feature or enhancement. For example, "RFE:
Implement a Foobar API". The description should be short. Since we use
specifications for details, we don't need to duplicate information in the body
of the bug report. After you create the bug, you can tag it with the "rfe" tag,
which helps people filter feature work from other bug reports. Finally, if your
specification has already merged, be sure to include a link to it as a comment.
If it hasn't, you can propose, or re-propose, your specification with
``Partial-Bug:`` followed by the bug number, at the bottom of your commit
message. The OpenStack Infrastructure bot automatically updates the RFE bug
report you just created with a link to the proposed specification. The
specification template explains how to link to RFE bug reports, which should
prompt you to open your RFE bug prior to proposing your specification.

If your feature is broken up into multiple commits, make sure to include
``Partial-Bug`` in your commit messages. Additionally, use ``Closes-Bug`` in
the last commit implementing the feature. This process ensures all patches
written for a feature are tracked in the bug report, making it easier to audit.
If you miss the opportunity to use the ``Closes-Bug`` tag and your feature work
is complete, set the bug status to "Fix Committed".

Specifications
==============

We use specifications as a way to describe, in detail, the change that we're
making and why.

To write a specification, you can follow the template provided in the
repository. To start writing a new specification, copy the template to the
directory that fits the project and release you plan to target. For example, if
you want to propose a feature to keystone for the Stein release, you should do
the following:

.. code-block:: bash

   $ cp specs/template.rst specs/keystone/stein/feature-foobar.rst

Once you have a template in place, work through each section. Specifications
should be descriptive and include use cases that justify the work. There are
sections dedicated to the problem statement, the proposed solution, alternative
solutions, security concerns, among other things. These sections are meant to
prompt you to think about how your feature impacts users, operators,
developers, related projects, and the existing code base. The template acts as
a guide, so if you need to inject an ad-hoc section to describe additional
details of your feature, don't hesitate to add one. Do not remove sections from
the template that do not apply to your specification. Instead, simply explain
why your proposed change doesn't have an impact on that aspect of the template.
Propose your specification for review when you're ready for feedback:

.. code-block:: bash

   $ git review

The process for reviewing specifications is handled using Gerrit. We don't
restrict the specification selection process to a particular group of
individuals, which allows for open and collaborative feedback. We encourage
everyone to be a part of the review process. Applying a code-review methodology
to specifications allows different people to think through the problem you're
trying to solve. Everyone wants to ensure the best design possible, given
various resource constraints. This process takes time. Don't be discouraged if
it takes longer than you anticipated for your specification to get feedback. A
specification must have support (+2) from at least two keystone-spec core
reviewers and it is typically approved (+Workflow) by the PTL, in order to be
formally accepted.
