--
-- Clean up the DB
--

delete from users;
delete from tenants;
delete from groups;
delete from user_group_association;
delete from user_tenant_association;
delete from token;
