-- =====================================================================
-- EGOS: Dagdag na TEST account sa PRONCR SOUTH (para sa cross-branch test)
-- Mabubura rin ito ng test_accounts_cleanup.sql (TESTEGOS prefix).
-- Walang password na kailangan: hindi ito gagamitin para mag-login.
-- =====================================================================

INSERT INTO users (username, password, role, facility, branch, account_type, status, email, employee_id_no)
VALUES ('TESTEGOS-SOUTH', crypt(encode(gen_random_bytes(16), 'hex'), gen_salt('bf')),
        'STAFF', 'GAMOT PROCESSOR', 'PRONCR SOUTH', 'STAFF', 'APPROVED',
        'testegos-south@example.invalid', 'TESTEGOS-SOUTH');

UPDATE users SET id_no = 'EOGS-' || LPAD(id::TEXT, 5, '0') WHERE username = 'TESTEGOS-SOUTH';

-- Pag-check: dapat 1 row, PRONCR SOUTH
SELECT username, role, branch, status FROM users WHERE username = 'TESTEGOS-SOUTH';
