--
--  Test Setup
--

-- Users

insert into users (id, password, email, enabled) values
       ("joeuser", "secrete", "joe@rackspace.com", 1);

insert into users (id, password, email, enabled) values
       ("admin", "secrete", "admin@rackspace.com", 1);

insert into users (id, password, email, enabled) values
       ("disabled", "secrete", "disable@rackspace.com", 0);

-- Tenants

insert into tenants (id, "desc", enabled) values
       ("1234", "This is a tenant", 1);

insert into tenants (id, "desc", enabled) values
       ("0000", "This one is disabled", 0);

-- Groups

insert into groups (id, "desc", tenant_id) values
       ("Admin", "Andmin users", "1234");

insert into groups (id, "desc", tenant_id) values
       ("Default", "Standard users", "1234");


-- User Group Associations

insert into user_group_association values
       ("joeuser", "Default");

insert into user_group_association values
       ("disabled", "Default");

insert into user_group_association values
       ("admin", "Admin");

-- User Tenant Associations

insert into user_tenant_association values
       ("joeuser", "1234");

insert into user_tenant_association values
       ("disabled", "1234");

insert into user_tenant_association values
       ("admin", "1234");

-- Token

insert into token values
       ("887665443383838", "joeuser", "1234", datetime("2012-02-05T00:00"));

insert into token values
       ("999888777666", "admin", "1234", datetime("2015-02-05T00:00"));

insert into token values
       ("000999", "admin", "1234", datetime("2010-02-05T00:00"));

insert into token values
       ("999888777", "disabled", "1234", datetime("2015-02-05T00:00"));

