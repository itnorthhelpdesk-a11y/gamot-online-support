-- =====================================================================
-- EGOS Security Fix, Hakbang 1: Burahin ang mga luma at hindi ginagamit na functions
-- Petsa: 2026-10-15
--
-- BAKIT:
--   A. 18 lumang bersyon (overloads) ng mga function ang naiwan pa sa database.
--      Walang audit logging ang mga ito at ang iba ay walang security check
--      (hal. set_branch_admin na walang YAKAP IT check; register_user na
--      nagse-save ng plain-text password). Kayang tawagin ito ng kahit sino.
--   B. 4 na function na hindi na ginagamit ng index.html o ng Edge Functions.
--      Ang get_refiled_deficiencies at get_branch_deficiencies ay nagbabalik
--      ng records sa kahit sinong hindi naka-login.
--   C. log_audit_trail / log_account_audit ay kayang tawagin nang direkta
--      ng kahit sino, kaya puwedeng magdagdag ng pekeng audit entries.
--      (Tinatawag pa rin sila ng ibang functions sa loob ng database, kaya
--      gagana pa rin ang audit logging.)
--
-- NA-VERIFY:
--   - Ang index.html ay laging nagpapasa ng p_performed_by / p_performed_by_username
--     at p_send_to_pharmacy, kaya ang PINAKABAGONG bersyon lang ang ginagamit.
--   - Walang Edge Function na tumatawag sa alinman sa mga function na ito.
--
-- ROLLBACK: 2026-10-15_01_rollback.sql (ibinabalik ang mga binurang functions)
-- =====================================================================

BEGIN;

-- ---------- A. Mga lumang overload (ang bagong bersyon ay MANANATILI) ----------
DROP FUNCTION IF EXISTS public.admin_reset_password(text, text, text);
DROP FUNCTION IF EXISTS public.approve_pharmacy_staff(text, text, text, text);
DROP FUNCTION IF EXISTS public.approve_user(text, text, text, text);
DROP FUNCTION IF EXISTS public.encode_deficiency(text, text, text, text, text, text, text, text, text, text, text);
DROP FUNCTION IF EXISTS public.encode_deficiency(text, text, text, text, text, text, text, text, text, text, text, text);
DROP FUNCTION IF EXISTS public.encode_deficiency(text, text, text, text, text, text, text, text, text, text, text, text, numeric);
DROP FUNCTION IF EXISTS public.pharmacy_admin_reset_password(text, text, text);
DROP FUNCTION IF EXISTS public.register_user(text, text, text, text, text);
DROP FUNCTION IF EXISTS public.resolve_deficiency(text, text);
DROP FUNCTION IF EXISTS public.set_branch_admin(text, boolean);
DROP FUNCTION IF EXISTS public.set_staff_active_status(text, text, boolean);
DROP FUNCTION IF EXISTS public.set_staff_active_status_by_admin(text, text, boolean);
DROP FUNCTION IF EXISTS public.toggle_gatn_paid_status(text, boolean);
DROP FUNCTION IF EXISTS public.update_staff_email(text, text, text);
DROP FUNCTION IF EXISTS public.update_staff_email_by_admin(text, text, text);
DROP FUNCTION IF EXISTS public.update_staff_employee_id_by_admin(text, text, text);
DROP FUNCTION IF EXISTS public.update_staff_pin(text, text, text);
DROP FUNCTION IF EXISTS public.update_tracker_fields(text, text, text, text, date);

-- ---------- B. Mga function na hindi na ginagamit ----------
DROP FUNCTION IF EXISTS public.generate_password_reset_otp(text);
DROP FUNCTION IF EXISTS public.get_refiled_deficiencies();
DROP FUNCTION IF EXISTS public.get_approved_staff_accounts(text);
DROP FUNCTION IF EXISTS public.get_branch_deficiencies(text);

-- ---------- C. Bawal nang direktang tawagin ang audit loggers ----------
REVOKE EXECUTE ON FUNCTION public.log_audit_trail(text, text, text, text, text) FROM PUBLIC, anon, authenticated;
REVOKE EXECUTE ON FUNCTION public.log_account_audit(text, text, text, text, text) FROM PUBLIC, anon, authenticated;

COMMIT;

-- ---------- PAG-CHECK (patakbuhin pagkatapos) ----------
-- 1) Dapat 1 row lang kada function name (wala nang duplicate):
--    SELECT proname, COUNT(*) FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
--    WHERE n.nspname = 'public' GROUP BY proname HAVING COUNT(*) > 1;
--    -> inaasahang resulta: walang row
--
-- 2) Dapat false ang anon_exec at auth_exec:
--    SELECT proname,
--           has_function_privilege('anon', p.oid, 'EXECUTE') AS anon_exec,
--           has_function_privilege('authenticated', p.oid, 'EXECUTE') AS auth_exec
--    FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
--    WHERE n.nspname = 'public' AND proname IN ('log_audit_trail', 'log_account_audit');
