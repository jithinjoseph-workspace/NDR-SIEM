-- Runs before init.sql (00- prefix) as the built-in default user on fresh start.
-- Grants ndr user full superuser access so it can create tenant databases.
CREATE USER IF NOT EXISTS ndr IDENTIFIED BY 'ndr123';
GRANT ALL ON *.* TO ndr WITH GRANT OPTION;
