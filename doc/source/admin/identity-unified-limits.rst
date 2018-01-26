==============
Unified Limits
==============

.. WARNING::

    The unified limits API is currently labeled as experimental and can change
    in backwards incompatible ways. After we get feedback on the intricacies of
    the API and no longer expect to make API breaking changes, the API will be
    marked as stable.

As of the Queens release, keystone has the ability to store and relay
information known as a limit. Limits can be used by services to enforce quota
on resources across OpenStack. This section describes the basic concepts of
limits, how the information can be consumed by services, and how operators can
manage resource quota across OpenStack using limits.

What is a limit?
================

A limit is a threshold for resource management and helps control resource
utilization. A process for managing limits allows for reallocation of resources
to different users or projects as needs change. Some information needed to
establish a limit may include:

- project_id
- API service type (e.g. compute, network, object-storage)
- a resource type (e.g. ram_mb, vcpus, security-groups)
- a default limit
- a project specific limit
- user_id (optional)
- a region (optional depending on the service)

Since keystone is the source of truth for nearly everything in the above list,
limits are a natural fit as a keystone resource. Two different limit resources
exist in this design. The first is a registered limit and the second is a
project limit.

Registered limits
-----------------

A registered limit accomplishes two important things in order to enforce quota
across multi-tenant, distributed systems. First, it establishes resource types
and associates them to services. Second, it sets a default resource limit for
all projects. The first part maps specific resource types to the services that
provide them. For example, a registered limit can map `vcpus`, to the compute
service. The second part sets a default of 20 `vcpus` per project. This
provides all the information needed for basic quota enforcement for any
resource provided by a service.

Project limits
--------------

A project limit is a limit associated to a specific project and it acts as an
override for a registered limit. A project limit still requires a resource type
and service, both of which must exist as a registered limit. For example, let's
assume a registered limit exists for `vcpus` provided by the compute service.
It wouldn't be possible for a project limit to be created for `cores` on the
compute service for a specific project. Project limits can only override limits
that have already been registered. In a general sense, registered limits are
likely established when a new service or cloud is deployed. Project limits are
used continuously to manage the flow of resource allocation.

Together, registered limits and project limits give deployments the ability to
restrict resources across the deployment by default, while being flexible
enough to freely marshal resources across projects.

Limits and usage
================

When we talk about a quota system, we’re really talking about two systems. A
system for setting and maintaining limits, the theoretical maximum usage, and a
system for enforcing that usage does not exceed limits. While they are coupled,
they are distinct.

Up to this point, we've established that keystone is the system for maintaining
limit information. Keystone’s responsibility is to ensuring that any changes to
limits are consistent with related limits currently stored in keystone.

Individual services maintain and enforce usage. Services check for enforcement
against the current limits at the time a resource allocation is requested by a
particular user. A usage reflects the actual allocation of units of a
particular resource to a consumer.

Given the above, the following is a possible and legal flow:

- User Jane is in project Foo
- Project Foo has a default CPU limit of 20
- User Jane allocated 18 CPUs in project Foo
- Administrator Kelly sets project Foo CPU limit to 10
- User Jane can no longer allocate instance resources in project Foo, until
  she (or others in the project) have deleted at least 9 CPUs to get under the
  new limit

The following would be another permuation:

- User Jane is in project Foo
- Project Foo has a default CPU limit of 20
- User Jane allocated 20 CPUs in project Foo
- User Jane attempts to create another instance, which results in a failed
  resource request since the request would violate usage based on the current
  limit of CPUs
- User Jane requests more resources
- Administrator Kelly adjust the project limit for Foo to be 30 CPUs
- User Jane resends her request for an instance, which successed since the
  useage for project Foo is under the project limit of 30 CPUs

This behavior lets administrators set the policy of what the future should be
when convenient, and prevent those projects from creating any more resources
that would exceed the limits in question. Members of a project can fix this for
themselves by bringing down the project usage to where there is now headroom.
If they don’t, at some point the administrators can more aggressively delete
things themselves.
