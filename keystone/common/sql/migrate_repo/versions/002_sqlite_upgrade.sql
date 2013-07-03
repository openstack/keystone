CREATE TABLE token_backup (
    id_hash VARCHAR(64) NOT NULL,
    id VARCHAR(1024),
    expires DATETIME,
    extra TEXT,
    PRIMARY KEY (id_hash)
);

insert into token_backup
    select id as old_id,
    '',
    expires as old_expires,
    extra as old_extra from token;

drop table token;

CREATE TABLE token (
    id_hash VARCHAR(64) NOT NULL,
    id VARCHAR(1024),
    expires DATETIME,
    extra TEXT,
    PRIMARY KEY (id_hash)
);

insert into token select * from token_backup;

drop table token_backup;
