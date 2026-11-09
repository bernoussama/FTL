CREATE TABLE queries ( id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp INTEGER NOT NULL, type INTEGER NOT NULL, status INTEGER NOT NULL, domain TEXT NOT NULL, client TEXT NOT NULL, forward TEXT );
CREATE INDEX idx_queries_timestamp ON queries (timestamp);
CREATE TABLE ftl ( id INTEGER PRIMARY KEY NOT NULL, value BLOB NOT NULL );
INSERT INTO ftl VALUES(0,1);
INSERT INTO ftl VALUES(1,0);
INSERT INTO queries (timestamp, type, status, domain, client, forward) VALUES (1700000000, 1, 2, 'example.com', '192.0.2.1', '8.8.8.8'), (1700000001, 28, 1, 'ads.example.net', '192.0.2.2', NULL);
