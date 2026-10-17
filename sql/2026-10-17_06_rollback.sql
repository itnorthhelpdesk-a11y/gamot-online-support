-- =====================================================================
-- ROLLBACK para sa 2026-10-17_06_search_path.sql
-- Ibinabalik sa dati (walang nakatakdang search_path) ang 4 na function.
-- =====================================================================

BEGIN;

ALTER FUNCTION public.log_audit_trail(text, text, text, text, text) RESET search_path;
ALTER FUNCTION public.log_account_audit(text, text, text, text, text) RESET search_path;
ALTER FUNCTION public._audit_change(text, text, text) RESET search_path;
ALTER FUNCTION public._block_denied_changes() RESET search_path;

COMMIT;
