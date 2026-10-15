-- =====================================================================
-- EGOS: Gumawa ng TEST accounts (PRONCR NORTH)
-- Burahin pagkatapos gamit ang: test_accounts_cleanup.sql
--
-- BAGO PATAKBUHIN: palitan ang ILAGAY_ANG_PASSWORD_DITO sa ibaba
-- (iisang password para sa lahat ng test account; 8+ chars, may
-- uppercase, lowercase at number). HUWAG i-commit ang file na may password.
--
-- Mga accounts na gagawin:
--   TESTEGOS-ADMIN     Branch Admin  (YAKAP IT, PRONCR NORTH)
--   TESTEGOS-STAFF     Staff         (GAMOT PROCESSOR, PRONCR NORTH)
--   TESTEGOS-PHARMA    Pharmacy Admin (accreditation P91999999)
--   TESTEGOS-PENDING1  Pending Staff  (para i-test ang APPROVE)
--   TESTEGOS-PENDING2  Pending Staff  (para i-test ang DECLINE)
-- =====================================================================

DO $$
DECLARE
  v_pw TEXT := 'ILAGAY_ANG_PASSWORD_DITO';
BEGIN
  IF v_pw = 'ILAGAY_ANG_PASSWORD_DITO' THEN
    RAISE EXCEPTION 'Palitan muna ang password sa itaas bago patakbuhin.';
  END IF;

  IF EXISTS (SELECT 1 FROM users WHERE username ILIKE 'TESTEGOS%') THEN
    RAISE EXCEPTION 'May TESTEGOS accounts na. Patakbuhin muna ang test_accounts_cleanup.sql.';
  END IF;

  INSERT INTO users (username, password, role, facility, branch, account_type, status,
                     accreditation_no, email, philhealth_pin, employee_id_no)
  VALUES
    ('TESTEGOS-ADMIN',    crypt(v_pw, gen_salt('bf')), 'BRANCH_ADMIN',   'YAKAP IT',          'PRONCR NORTH', 'STAFF',    'APPROVED', NULL,          'testegos-admin@example.invalid',    NULL,              'TESTEGOS-ADMIN'),
    ('TESTEGOS-STAFF',    crypt(v_pw, gen_salt('bf')), 'STAFF',          'GAMOT PROCESSOR',   'PRONCR NORTH', 'STAFF',    'APPROVED', NULL,          'testegos-staff@example.invalid',    NULL,              'TESTEGOS-STAFF'),
    ('TESTEGOS-PHARMA',   crypt(v_pw, gen_salt('bf')), 'PHARMACY_ADMIN', 'TESTEGOS PHARMACY', 'PRONCR NORTH', 'PHARMACY', 'APPROVED', 'P91999999','testegos-pharma@example.invalid',   'TESTEGOS-PHARMA', NULL),
    ('TESTEGOS-PENDING1', crypt(v_pw, gen_salt('bf')), 'STAFF',          'GAMOT PROCESSOR',   'PRONCR NORTH', 'STAFF',    'PENDING',  NULL,          'testegos-pending1@example.invalid', NULL,              'TESTEGOS-PENDING1'),
    ('TESTEGOS-PENDING2', crypt(v_pw, gen_salt('bf')), 'STAFF',          'GAMOT PROCESSOR',   'PRONCR NORTH', 'STAFF',    'PENDING',  NULL,          'testegos-pending2@example.invalid', NULL,              'TESTEGOS-PENDING2');

  -- Parehong format ng id_no na ibinibigay ng approve_user
  UPDATE users SET id_no = 'EOGS-' || LPAD(id::TEXT, 5, '0')
  WHERE username IN ('TESTEGOS-ADMIN', 'TESTEGOS-STAFF', 'TESTEGOS-PHARMA');
END $$;

-- Pag-check: dapat 5 rows
SELECT username, role, account_type, branch, facility, status, id_no, accreditation_no
FROM users WHERE username ILIKE 'TESTEGOS%' ORDER BY username;
