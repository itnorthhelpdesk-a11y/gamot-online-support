-- ROLLBACK ng 2026-11-24_13_system_analytics.sql
-- Tinatanggal lang ang bagong function. Walang data na nagbago.
-- Paalala: itago muna ang System Monitor tab (ibalik ang lumang index.html)
-- bago ito patakbuhin, para walang error sa page.

BEGIN;
DROP FUNCTION IF EXISTS public.get_system_analytics();
COMMIT;
