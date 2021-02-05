====================
Policy configuration
====================

.. warning::

   JSON formatted policy file is deprecated since Keystone 19.0.0 (Wallaby).
   This `oslopolicy-convert-json-to-yaml`__ tool will migrate your existing
   JSON-formatted policy file to YAML in a backward-compatible way.

.. __: https://docs.openstack.org/oslo.policy/latest/cli/oslopolicy-convert-json-to-yaml.html


Configuration
~~~~~~~~~~~~~

The following is an overview of all available policies in Keystone.

.. only:: html

   For a sample configuration file, refer to :doc:`samples/policy-yaml`.

.. show-policy::
   :config-file: ../../config-generator/keystone-policy-generator.conf
