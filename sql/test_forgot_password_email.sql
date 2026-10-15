-- =====================================================================
-- EGOS TEST: lagyan ng totoong email ang TESTEGOS-STAFF para ma-test ang
-- Forgot Password (dadating ang code sa inbox ng itnorthhelpdesk@gmail.com;
-- ang "+egostest" ay pinapansin ng Gmail bilang parehong inbox).
-- Mabubura ito ng test_accounts_cleanup.sql.
-- =====================================================================

UPDATE users SET email = 'itnorthhelpdesk+egostest@gmail.com' WHERE username = 'TESTEGOS-STAFF';

SELECT username, email FROM users WHERE username = 'TESTEGOS-STAFF';
