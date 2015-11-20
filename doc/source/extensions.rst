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

==========
Extensions
==========

Status
======

An extension may be considered ``stable``, ``experimental`` or ``out-of-tree``.

* A `stable` status indicates that an extension is fully supported by the
  OpenStack Identity team.

* An `experimental` status indicates that although the intention is to keep
  the API unchanged, we reserve the right to change it up until the point that
  it is deemed `stable`.

* An `out-of-tree` status indicates that no formal support will be provided.

Graduation Process
==================

By default, major new functionality that is proposed to be in-tree will start
off in `experimental` status. Typically it would take at minimum of one cycle
to transition from `experimental` to `stable`, although in special cases this
might happened within a cycle.

Removal Process
===============

It is not intended that functionality should stay in experimental for a long
period, functionality that stays `experimental` for more than **two** releases
would be expected to make a transition to either `stable` or `out-of-tree`.
