=================================
  Keystone Installation Tutorial
=================================

The OpenStack system consists of several key services that are separately
installed. These services work together depending on your cloud
needs and include the Compute, Identity, Networking, Image, Block Storage,
Object Storage, Telemetry, Orchestration, and Database services. You
can install any of these projects separately and configure them stand-alone
or as connected entities.

This section describes how to install and configure the OpenStack
Identity service, code-named keystone, on the controller node. For
scalability purposes, this configuration deploys Fernet tokens and
the Apache HTTP server to handle requests.

.. toctree::
   :maxdepth: 3

   index-obs
   index-rdo
   index-ubuntu
