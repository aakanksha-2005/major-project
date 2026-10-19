-- Runs once, on first initialization of the PostgreSQL volume.
-- Creates the ISOLATED test database used by `pytest -m postgres`.
-- The test fixtures also re-check this at runtime (pre-existing volumes).
CREATE DATABASE rasp_test;
