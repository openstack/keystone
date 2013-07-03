drop table token;

CREATE TABLE token (
    id VARCHAR(64) NOT NULL,
    expires DATETIME,
    extra TEXT,
    PRIMARY KEY (id)
);
