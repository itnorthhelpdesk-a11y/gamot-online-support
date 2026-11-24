-- =====================================================================
-- ROLLBACK ng 2026-11-24_18_registration_precheck.sql
-- Ibinabalik ang register_user sa bersyon ng SQL 17, at tinatanggal ang
-- precheck_registration at _registration_problem.
-- PAALALA: kung naka-live na ang page na tumatawag sa precheck_registration,
--   i-revert muna ang page bago i-run ito (kung hindi, hindi makakapag-register).
-- =====================================================================

BEGIN;

CREATE OR REPLACE FUNCTION public.register_user(p_username text, p_password text, p_account_type text, p_facility text, p_branch text, p_accreditation_no text, p_email text, p_attachment_link text, p_philhealth_pin text, p_employee_id_no text)
 RETURNS json
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path = public, extensions
AS $function$
DECLARE
  v_existing INT;
  v_existing_email INT;
  v_role TEXT;
  v_recent_attempts INT;
  v_daily_attempts INT;
  v_username TEXT := UPPER(TRIM(COALESCE(p_username, '')));
  v_accred TEXT := UPPER(TRIM(COALESCE(p_accreditation_no, '')));
  v_linked_hash TEXT;
  v_linked_list TEXT;
BEGIN
  IF position('@' IN v_username) > 0 THEN
    RETURN json_build_object('success', false, 'message', 'The username must not contain "@".');
  END IF;

  -- May account na ba ang PIN na ito sa ibang pharmacy?
  IF UPPER(p_account_type) = 'PHARMACY' THEN
    IF EXISTS (
      SELECT 1 FROM users
      WHERE account_type = 'PHARMACY'
        AND _pharmacy_pin(username) = v_username
        AND status != 'REJECTED'
        AND UPPER(accreditation_no) = v_accred
    ) THEN
      RETURN json_build_object('success', false, 'message', 'This PhilHealth Identification Number (PIN) is already registered for this pharmacy (accreditation no.). If this is your account, please use "Forgot Password" instead.');
    END IF;

    SELECT password INTO v_linked_hash
    FROM users
    WHERE account_type = 'PHARMACY'
      AND _pharmacy_pin(username) = v_username
      AND status != 'REJECTED'
    ORDER BY (status = 'APPROVED') DESC, id
    LIMIT 1;
  END IF;

  IF v_linked_hash IS NOT NULL THEN
    -- Dagdag na pharmacy: patunayang siya ang may-ari ng PIN
    IF v_linked_hash IS DISTINCT FROM crypt(COALESCE(p_password, ''), v_linked_hash) THEN
      RETURN json_build_object('success', false, 'message', 'This PIN already has an EGOS account in another pharmacy. To add this pharmacy, enter your CURRENT EGOS password in the Password field (one password is used for all your pharmacies).');
    END IF;
    IF v_accred = '' THEN
      RETURN json_build_object('success', false, 'message', 'Please enter the Facility Accreditation No. of the pharmacy you are adding.');
    END IF;
  ELSE
    IF LENGTH(p_password) < 8 THEN
      RETURN json_build_object('success', false, 'message', 'Password must be at least 8 characters long.');
    END IF;

    IF p_password !~ '[A-Z]' THEN
      RETURN json_build_object('success', false, 'message', 'Password must contain at least one uppercase letter.');
    END IF;

    IF p_password !~ '[a-z]' THEN
      RETURN json_build_object('success', false, 'message', 'Password must contain at least one lowercase letter.');
    END IF;

    IF p_password !~ '[0-9]' THEN
      RETURN json_build_object('success', false, 'message', 'Password must contain at least one number.');
    END IF;
  END IF;

  -- ang server na mismo ang nagche-check na na-verify ang email
  IF NOT EXISTS (
    SELECT 1 FROM registration_email_verifications
    WHERE LOWER(email) = LOWER(p_email)
      AND verified_at > NOW() - INTERVAL '2 hours'
  ) THEN
    RETURN json_build_object('success', false, 'message', 'Please verify your email address first (the verification is valid for 2 hours).');
  END IF;

  -- hindi kasama ang REJECTED (declined) accounts sa email uniqueness check
  SELECT COUNT(*) INTO v_existing_email
  FROM users
  WHERE LOWER(email) = LOWER(p_email)
    AND status != 'REJECTED';

  IF v_existing_email > 0 THEN
    RETURN json_build_object('success', false, 'message', 'This email address is already registered to another account. Please use a different email (each pharmacy account needs its own email), or use "Forgot Password" if this is your account.');
  END IF;

  SELECT COUNT(*) INTO v_recent_attempts
  FROM registration_attempts
  WHERE LOWER(email) = LOWER(p_email) AND attempted_at > NOW() - INTERVAL '10 minutes';

  IF v_recent_attempts > 0 THEN
    RETURN json_build_object('success', false, 'message', 'Please wait a few minutes before trying to register again with this email.');
  END IF;

  SELECT COUNT(*) INTO v_daily_attempts
  FROM registration_attempts
  WHERE LOWER(email) = LOWER(p_email) AND attempted_at > NOW() - INTERVAL '24 hours';

  IF v_daily_attempts >= 5 THEN
    RETURN json_build_object('success', false, 'message', 'Too many registration attempts with this email today. Please try again tomorrow or contact support.');
  END IF;

  INSERT INTO registration_attempts (email) VALUES (p_email);

  -- Dagdag na pharmacy: PIN@ACCRED ang username kung gamit na ang PIN mismo
  IF v_linked_hash IS NOT NULL AND EXISTS (
    SELECT 1 FROM users WHERE UPPER(username) = v_username AND status != 'REJECTED'
  ) THEN
    v_username := v_username || '@' || v_accred;
  END IF;

  -- hindi kasama ang REJECTED accounts sa username uniqueness check
  SELECT COUNT(*) INTO v_existing
  FROM users
  WHERE UPPER(username) = v_username
    AND status != 'REJECTED';

  IF v_existing > 0 THEN
    IF UPPER(p_account_type) = 'STAFF' THEN
      RETURN json_build_object('success', false, 'message', 'This PhilHealth Employee ID No. is already registered to another account. If this is your account, please use "Forgot Password" instead.');
    ELSE
      RETURN json_build_object('success', false, 'message', 'This PhilHealth Identification Number (PIN) is already registered to another account. If this is your account, please use "Forgot Password" instead.');
    END IF;
  END IF;

  v_role := CASE WHEN UPPER(p_account_type) = 'STAFF' THEN 'STAFF' ELSE 'USER' END;

  -- Declined account na nagre-register ulit: gamitin ang dating row (UNIQUE ang username sa DB)
  UPDATE users
  SET password = COALESCE(v_linked_hash, crypt(p_password, gen_salt('bf'))),
      role = v_role,
      facility = UPPER(p_facility),
      branch = UPPER(p_branch),
      account_type = p_account_type,
      status = 'PENDING',
      accreditation_no = UPPER(p_accreditation_no),
      email = p_email,
      attachment_link = p_attachment_link,
      philhealth_pin = p_philhealth_pin,
      employee_id_no = p_employee_id_no,
      decline_reason = NULL
  WHERE UPPER(username) = v_username
    AND status = 'REJECTED';

  IF FOUND THEN
    PERFORM log_account_audit(v_username, 'RE_REGISTERED', v_username, UPPER(p_branch), 'Declined account registered again with a new password and details.');
  ELSE
    BEGIN
      INSERT INTO users (username, password, role, facility, branch, account_type, status, accreditation_no, email, attachment_link, philhealth_pin, employee_id_no)
      VALUES (v_username, COALESCE(v_linked_hash, crypt(p_password, gen_salt('bf'))), v_role, UPPER(p_facility), UPPER(p_branch), p_account_type, 'PENDING', UPPER(p_accreditation_no), p_email, p_attachment_link, p_philhealth_pin, p_employee_id_no);
    EXCEPTION WHEN unique_violation THEN
      RETURN json_build_object('success', false, 'message', 'This ID or email is already registered to another account. If this is your account, please use "Forgot Password" instead.');
    END;
  END IF;

  IF v_linked_hash IS NOT NULL THEN
    SELECT string_agg(username || ' (' || COALESCE(accreditation_no, '—') || ', ' || COALESCE(branch, '—') || ', ' || status || ')', '; ' ORDER BY id)
      INTO v_linked_list
    FROM users
    WHERE account_type = 'PHARMACY'
      AND _pharmacy_pin(username) = _pharmacy_pin(v_username)
      AND UPPER(username) <> v_username
      AND status != 'REJECTED';

    PERFORM log_account_audit(v_username, 'REGISTERED_ADDITIONAL_PHARMACY', v_username, UPPER(p_branch),
      'Same PIN registered for another pharmacy. Other accounts: ' || COALESCE(v_linked_list, '—'));
  END IF;

  -- gamit na ang verification (hindi na puwedeng gamitin ulit)
  DELETE FROM registration_email_verifications WHERE LOWER(email) = LOWER(p_email);

  RETURN json_build_object('success', true, 'additional_pharmacy', v_linked_hash IS NOT NULL);
END;
$function$;

DROP FUNCTION IF EXISTS public.precheck_registration(text, text, text, text, text);
DROP FUNCTION IF EXISTS public._registration_problem(text, text, text, text, text);

COMMIT;
