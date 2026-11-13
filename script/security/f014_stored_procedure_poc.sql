-- F-014 isolated proof of concept: selective SECURITY INVOKER function with
-- REVOKE FROM PUBLIC + GRANT EXECUTE to an authorized role only.
-- Creates synthetic schema/roles, verifies allow/deny, then drops everything.
-- Does not modify Foreman application tables.
--
-- Usage: psql "$DATABASE_URL" -v ON_ERROR_STOP=1 -f script/security/f014_stored_procedure_poc.sql

BEGIN;

DROP SCHEMA IF EXISTS f014_poc CASCADE;
DROP ROLE IF EXISTS f014_app;
DROP ROLE IF EXISTS f014_denied;
DROP ROLE IF EXISTS f014_migrator;

CREATE ROLE f014_migrator NOINHERIT;
CREATE ROLE f014_app NOINHERIT LOGIN PASSWORD 'f014_app_poc';
CREATE ROLE f014_denied NOINHERIT LOGIN PASSWORD 'f014_denied_poc';

CREATE SCHEMA f014_poc AUTHORIZATION f014_migrator;
GRANT USAGE ON SCHEMA f014_poc TO f014_app;

SET ROLE f014_migrator;

CREATE TABLE f014_poc.synthetic_items (
  id serial PRIMARY KEY,
  name text NOT NULL CHECK (char_length(name) BETWEEN 1 AND 64)
);
ALTER TABLE f014_poc.synthetic_items OWNER TO f014_migrator;

GRANT SELECT, INSERT, UPDATE, DELETE ON f014_poc.synthetic_items TO f014_app;
GRANT USAGE, SELECT ON SEQUENCE f014_poc.synthetic_items_id_seq TO f014_app;

CREATE OR REPLACE FUNCTION f014_poc.insert_item(p_name text)
RETURNS integer
LANGUAGE plpgsql
SECURITY INVOKER
SET search_path = f014_poc, pg_temp
AS $fn$
DECLARE
  new_id integer;
BEGIN
  IF p_name IS NULL OR length(btrim(p_name)) = 0 OR length(p_name) > 64 THEN
    RAISE EXCEPTION 'invalid name' USING ERRCODE = '22023';
  END IF;
  INSERT INTO synthetic_items(name) VALUES (btrim(p_name)) RETURNING id INTO new_id;
  RETURN new_id;
END;
$fn$;

ALTER FUNCTION f014_poc.insert_item(text) OWNER TO f014_migrator;
REVOKE ALL ON FUNCTION f014_poc.insert_item(text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION f014_poc.insert_item(text) TO f014_app;

RESET ROLE;

SET ROLE f014_app;
SELECT f014_poc.insert_item('alpha') AS inserted_id;
SELECT count(*) AS app_select_count FROM f014_poc.synthetic_items;
RESET ROLE;

DO $$
DECLARE
  breached boolean := false;
BEGIN
  BEGIN
    SET ROLE f014_denied;
    PERFORM f014_poc.insert_item('evil');
    breached := true;
  EXCEPTION WHEN insufficient_privilege OR undefined_function THEN
    breached := false;
  END;
  RESET ROLE;
  IF breached THEN
    RAISE EXCEPTION 'FAIL: f014_denied executed insert_item';
  END IF;
  RAISE NOTICE 'PASS: f014_denied cannot EXECUTE insert_item';
END$$;

DO $$
DECLARE
  breached boolean := false;
BEGIN
  BEGIN
    SET ROLE f014_denied;
    PERFORM 1 FROM f014_poc.synthetic_items;
    breached := true;
  EXCEPTION WHEN insufficient_privilege THEN
    breached := false;
  END;
  RESET ROLE;
  IF breached THEN
    RAISE EXCEPTION 'FAIL: f014_denied selected synthetic_items';
  END IF;
  RAISE NOTICE 'PASS: f014_denied cannot SELECT synthetic_items';
END$$;

SELECT has_function_privilege('public', 'f014_poc.insert_item(text)', 'EXECUTE') AS public_execute,
       has_function_privilege('f014_app', 'f014_poc.insert_item(text)', 'EXECUTE') AS app_execute,
       has_function_privilege('f014_denied', 'f014_poc.insert_item(text)', 'EXECUTE') AS denied_execute;

DROP SCHEMA f014_poc CASCADE;
DROP ROLE f014_app;
DROP ROLE f014_denied;
DROP ROLE f014_migrator;

COMMIT;

SELECT 'F-014 PoC complete — synthetic objects removed' AS status;
