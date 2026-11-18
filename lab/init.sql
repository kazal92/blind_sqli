USE lab;
CREATE TABLE users (
    id INT PRIMARY KEY,
    username VARCHAR(40) NOT NULL UNIQUE,
    password VARCHAR(80) NOT NULL
);
INSERT INTO users VALUES
    (1, 'admin', 'lab-demo'),
    (2, 'alice', 'alice-demo'),
    (3, 'bob', 'bob-demo');
REVOKE ALL PRIVILEGES ON lab.* FROM 'lab_user'@'%';
GRANT SELECT ON lab.* TO 'lab_user'@'%';
