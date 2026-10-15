-- =====================================================================
-- EGOS TEST: lagyan ng totoong email ang TESTEGOS-STAFF para ma-test ang
-- Forgot Password (dadating ang code sa inbox ng itnorthhelpdesk@gmail.com).
-- Mabubura ito ng test_accounts_cleanup.sql (kasama ang TESTEGOS-STAFF).
-- =====================================================================

UPDATE users SET email = 'itnorthhelpdesk@gmail.com' WHERE username IN ('TESTEGOS-STAFF', 'TESTEGOS-PHARMA');

SELECT username, email FROM users WHERE username IN ('TESTEGOS-STAFF', 'TESTEGOS-PHARMA');
