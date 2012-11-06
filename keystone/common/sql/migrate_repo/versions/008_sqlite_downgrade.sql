-- not supported by sqlite, but should be:
-- alter TABLE tenant drop column description;
-- alter TABLE tenant drop column enabled;
-- The downgrade process will fail without valid SQL in this file
select count(*) from tenant;
