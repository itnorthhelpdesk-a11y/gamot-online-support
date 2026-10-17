-- =====================================================================
-- 2026-10-17_06  Itakda ang search_path ng 4 na audit / freeze function
-- Para laging sa "public" schema hahanapin ang mga table na ginagamit nila
-- (babala ng Supabase: "Function Search Path Mutable").
-- WALANG binabago sa laman o lohika ng mga function, at walang data na nagagalaw.
-- Rollback: 2026-10-17_06_rollback.sql
-- =====================================================================

BEGIN;

ALTER FUNCTION public.log_audit_trail(text, text, text, text, text) SET search_path = public;
ALTER FUNCTION public.log_account_audit(text, text, text, text, text) SET search_path = public;
ALTER FUNCTION public._audit_change(text, text, text) SET search_path = public;
ALTER FUNCTION public._block_denied_changes() SET search_path = public;

COMMIT;

-- Pang-check (dapat may "search_path=public" ang 4 na row):
-- SELECT proname, proconfig FROM pg_proc
-- WHERE pronamespace = 'public'::regnamespace
--   AND proname IN ('log_audit_trail','log_account_audit','_audit_change','_block_denied_changes');
