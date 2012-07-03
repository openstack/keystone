alter table token drop id;
alter table token change id_hash id varchar(64);

