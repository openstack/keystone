

General expected data model:

  ( tenants >--< users ) --< roles

  Tenants and Users have a many-to-many relationship.
  A given Tenant-User pair can have many Roles.


Tenant Schema:
  id: something big and unique
  name: something displayable
  .. created_at: datetime
  .. deleted_at: datetime

User Schema:
  id: something big and unique
  name: something displayable
  .. created_at: datetime
  .. deleted_at: datetime


General service model:

  (1) a web service with an API
  (2) a variety of backend storage schemes for tenant-user pairs.
  (3) a simple token datastore



