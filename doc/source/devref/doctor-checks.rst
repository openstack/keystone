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

============================
Developing ``doctor`` checks
============================

As noted in the section above, keystone's management CLI provides various tools
for administrating OpenStack Identity. One of those tools is called
``keystone-manage doctor`` and it is responsible for performing health checks
about the deployment. If ``keystone-manage doctor`` detects a symptom, it
will provide the operator with suggestions to improve the overall health of the
deployment. This section is dedicated to documenting how to write symptoms for
``doctor``.

The ``doctor`` tool consists of a list of symptoms. Each symptom is something
that we can check against, and provide a warning for if we detect a
misconfiguration. The ``doctor`` module is located in
:py:mod:`keystone.cmd.doctor`. The current checks are based heavily on
inspecting configuration values. As a result, many of the submodules within the
``doctor`` module are named after the configuration section for the symptoms
they check. For example, if we want to ensure the ``keystone.conf [DEFAULT]
max_token_size`` option is properly configured for whatever ``keystone.conf
[token] provider`` is set to, we can place that symptom in a module called
:py:mod:`keystone.cmd.doctor.tokens`. The symptom will be loaded by
importing the ``doctor`` module, which is done when ``keystone-manage doctor``
is invoked from the command line. When adding new symptoms, it's important to
remember to add new modules to the ``SYMPTOM_MODULES`` list in
:py:mod:`keystone.cmd.doctor.__init__`. Doing that will ensure ``doctor``
discovers properly named symptoms when executed.

Now that we know symptoms are organized according to configuration sections,
and how to add them, how exactly do we write a new symptom? ``doctor`` will
automatically discover new symptoms by inspecting the methods of each symptom
module (i.e. ``SYMPTOM_MODULES``). If a method declaration starts with
``def symptom_`` it is considered a symptom that ``doctor`` should check for,
and it should be run. The naming of the symptom, or method name, is extremely
important since ``doctor`` will use it to describe what it's doing to whoever
runs ``doctor``. In addition to a well named method, we also need to provide a
complete documentation string for the method. If ``doctor`` detects a symptom,
it will use the method's documentation string as feedback to the operator. It
should describe why the check is being done, why it was triggered, and possible
solutions to cure the symptom. For examples of this, see the existing symptoms
in any of ``doctor``'s symptom modules.

The last step is evaluating the logic within the symptom. As previously stated,
``doctor`` will check for a symptom if methods within specific symptom modules
make a specific naming convention. In order for ``doctor`` to suggest feedback,
it needs to know whether or not the symptom is actually present. We accomplish
this by making all symptoms return ``True`` when a symptom is present. When a
symptom evaluates to ``False``, ``doctor`` will move along to the next symptom
in the list since. If the deployment isn't suffering for a specific symptom,
``doctor`` should not suggest any actions related to that symptom (i.e. if
you have your cholesterol under control, why would a physician recommend
cholesterol medication if you don't need it).

To summarize:

- Symptoms should live in modules named according to the most relevant
  configuration section they apply to. This ensure we keep our symptoms
  organized, grouped, and easy to find.
- When writing symptoms for a new section, remember to add the module name to
  the ``SYMPTOM_MODULES`` list in :py:mod:`keystone.cmd.doctor.__init__`.
- Remember to use a good name for the symptom method signature and to prepend
  it with ``symptom_`` in order for it to be discovered automatically by
  ``doctor``.
- Symptoms have to evaluate to ``True`` in order to provide feedback to
  operators.
- Symptoms should have very thorough documentation strings that describe the
  symptom, side-effects of the symptom, and ways to remedy it.

For examples, feel free to run ``doctor`` locally using ``keystone-manage`` and
inspect the existing symptoms.
