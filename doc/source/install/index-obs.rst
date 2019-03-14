=====================================================================
Keystone Installation Tutorial for openSUSE and SUSE Linux Enterprise
=====================================================================

Abstract
~~~~~~~~

This guide will show you how to install OpenStack by using packages
on openSUSE Leap 42.2 and SUSE Linux Enterprise Server 12 - for
both SP1 and SP2 - through the Open Build Service Cloud repository.

Explanations of configuration options and sample configuration files
are included.

.. note::
   The Training Labs scripts provide an automated way of deploying the
   cluster described in this Installation Guide into VirtualBox or KVM
   VMs. You will need a desktop computer or a laptop with at least 8
   GB memory and 20 GB free storage running Linux, MacOS, or Windows.
   Please see the
   `OpenStack Training Labs <https://docs.openstack.org/training_labs/>`_.

.. warning::

   This guide is a work-in-progress and is subject to updates frequently.
   Pre-release packages have been used for testing, and some instructions
   may not work with final versions. Please help us make this guide better
   by reporting any errors you encounter.

Contents
~~~~~~~~

.. toctree::
   :maxdepth: 2

   get-started-obs
   keystone-install-obs
   keystone-users-obs
   keystone-verify-obs
   keystone-openrc-obs

.. Pseudo only directive for each distribution used by the build tool.
   This pseudo only directive for toctree only works fine with Tox.
   When you directly build this guide with Sphinx,
   some navigation menu may not work properly.
.. Keep this pseudo only directive not to break translation tool chain
   at the openstack-doc-tools repo until it is changed.
.. end of contents
