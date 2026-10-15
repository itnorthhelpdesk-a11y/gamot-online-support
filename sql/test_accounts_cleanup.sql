-- =====================================================================
-- EGOS: Burahin ang lahat ng TESTEGOS test data
-- Binubura: test accounts, test GATN records (TESTEGOS...), at ang mga
-- audit / reset / AI-chat / registration rows na para sa kanila.
-- HINDI ginagalaw ang totoong accounts at records.
--
-- HAKBANG 1: Patakbuhin muna ang SILIP (SELECT) para makita kung ilan ang mabubura.
-- HAKBANG 2: Kapag tama ang bilang, patakbuhin ang BEGIN ... COMMIT na bahagi.
-- =====================================================================

-- ---------- SILIP: ilan ang mabubura ----------
SELECT 'users' AS tbl, count(*) FROM users WHERE username ILIKE 'TESTEGOS%'
UNION ALL SELECT 'deficiency_records', count(*) FROM deficiency_records
  WHERE gatn_no ILIKE 'TESTEGOS%' OR facility_accreditation_no = 'P91999999'
UNION ALL SELECT 'audit_trail', count(*) FROM audit_trail
  WHERE gatn_no ILIKE 'TESTEGOS%' OR performed_by_username ILIKE 'TESTEGOS%'
UNION ALL SELECT 'account_audit_trail', count(*) FROM account_audit_trail
  WHERE username_affected ILIKE 'TESTEGOS%' OR performed_by_username ILIKE 'TESTEGOS%'
UNION ALL SELECT 'login_audit', count(*) FROM login_audit WHERE username ILIKE 'TESTEGOS%'
UNION ALL SELECT 'password_reset_requests', count(*) FROM password_reset_requests WHERE username ILIKE 'TESTEGOS%'
UNION ALL SELECT 'ai_chat_requests', count(*) FROM ai_chat_requests WHERE username ILIKE 'TESTEGOS%'
UNION ALL SELECT 'registration_attempts', count(*) FROM registration_attempts
  WHERE email ILIKE 'testegos%@example.invalid' OR email ILIKE 'itnorthhelpdesk+egos%@gmail.com'
UNION ALL SELECT 'registration_email_verifications', count(*) FROM registration_email_verifications
  WHERE email ILIKE 'testegos%@example.invalid' OR email ILIKE 'itnorthhelpdesk+egos%@gmail.com'
UNION ALL SELECT 'users (test email)', count(*) FROM users WHERE email ILIKE 'itnorthhelpdesk+egos%@gmail.com';

-- Records na in-encode ng test staff pero HINDI nagsimula sa TESTEGOS ang GATN
-- (hindi ito buburahin nang awtomatiko; dapat walang row dito):
SELECT r.gatn_no, r.created_at FROM deficiency_records r
JOIN audit_trail a ON a.gatn_no = r.gatn_no AND a.action = 'ENCODE'
WHERE a.performed_by_username ILIKE 'TESTEGOS%'
  AND r.gatn_no NOT ILIKE 'TESTEGOS%';

-- ---------- BURAHIN ----------
BEGIN;

-- Payagan ang pagbura ng DENIED test records (frozen ang DENIED; sa transaction na ito lang)
SELECT set_config('egos.allow_denied_change', 'on', true);

DELETE FROM mr_notice_queue WHERE gatn_no ILIKE 'TESTEGOS%';

DELETE FROM audit_trail
  WHERE gatn_no ILIKE 'TESTEGOS%' OR performed_by_username ILIKE 'TESTEGOS%';
DELETE FROM account_audit_trail
  WHERE username_affected ILIKE 'TESTEGOS%' OR performed_by_username ILIKE 'TESTEGOS%';
DELETE FROM deficiency_records
  WHERE gatn_no ILIKE 'TESTEGOS%' OR facility_accreditation_no = 'P91999999';
DELETE FROM login_audit WHERE username ILIKE 'TESTEGOS%';
DELETE FROM password_reset_requests WHERE username ILIKE 'TESTEGOS%';
DELETE FROM ai_chat_requests WHERE username ILIKE 'TESTEGOS%';
DELETE FROM registration_attempts
  WHERE email ILIKE 'testegos%@example.invalid' OR email ILIKE 'itnorthhelpdesk+egos%@gmail.com';
DELETE FROM registration_email_verifications
  WHERE email ILIKE 'testegos%@example.invalid' OR email ILIKE 'itnorthhelpdesk+egos%@gmail.com';
-- Test registration na gumamit ng itnorthhelpdesk+egos...@gmail.com (kasama ang audit nila)
DELETE FROM account_audit_trail WHERE username_affected IN
  (SELECT username FROM users WHERE email ILIKE 'itnorthhelpdesk+egos%@gmail.com');
DELETE FROM login_audit WHERE username IN
  (SELECT username FROM users WHERE email ILIKE 'itnorthhelpdesk+egos%@gmail.com');
DELETE FROM users WHERE email ILIKE 'itnorthhelpdesk+egos%@gmail.com';
DELETE FROM users WHERE username ILIKE 'TESTEGOS%';   -- kasama nang mabubura ang sessions (ON DELETE CASCADE)

COMMIT;
