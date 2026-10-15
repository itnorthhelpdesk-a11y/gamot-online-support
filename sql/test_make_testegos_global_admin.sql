-- =====================================================================
-- EGOS TEST: pansamantalang gawing GLOBAL ADMIN ang TESTEGOS-ADMIN
-- (para ma-test ang "Reopen" ng DENIED claim, na ADMIN lang ang puwede).
-- Mabubura ang account (kasama ang role na ito) ng test_accounts_cleanup.sql.
-- PATAKBUHIN ANG CLEANUP AGAD PAGKATAPOS NG TEST.
-- =====================================================================

UPDATE users SET role = 'ADMIN' WHERE username = 'TESTEGOS-ADMIN';

SELECT username, role, branch, status FROM users WHERE username = 'TESTEGOS-ADMIN';
