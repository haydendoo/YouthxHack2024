-- Delete existing table
DROP TABLE IF EXISTS users;

-- Create user table
CREATE TABLE users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT NOT NULL UNIQUE,
    password TEXT NOT NULL,
    verified INTEGER CHECK (verified IN (0, 1)) DEFAULT 0,
    token TEXT NOT NULL
);