-- =====================================================================
-- EGOS: I-check muna ang registration BAGO i-upload ang attachment,
--       at lockout sa maling password kapag nagdadagdag ng pharmacy
-- Petsa: 2026-11-24
--
-- PROBLEMA 1: kapag tinanggihan ang registration (hal. gamit na ang email),
--   naiiwan sa storage ang na-upload na PDF. Hindi ito kayang burahin ng
--   page (upload lang ang pinapayagan sa anon, at dapat ganoon).
--   AYOS: bagong precheck_registration() na tinatawag ng page bago mag-upload.
--
-- PROBLEMA 2 (galing sa SQL 17): sa pagdadagdag ng pharmacy, puwedeng
--   hulaan nang paulit-ulit ang password ng isang PIN.
--   AYOS: (a) kailangan munang verified ang email bago i-check ang password;
--         (b) ang maling password ay binibilang sa lockout ng login
--             (5 mali = naka-lock nang 15 minuto) at naka-log sa login_audit.
--
-- Iisang helper (_registration_problem) ang ginagamit ng precheck at ng
-- register_user, kaya pareho ang mga patakaran. Walang binago sa data.
-- ROLLBACK: 2026-11-24_18_rollback.sql
-- =====================================================================

BEGIN;

-- ---------- 1. Helper: ibinabalik ang dahilan kung bakit hindi puwede (o NULL) ----------
CREATE OR REPLACE FUNCTION public._registration_problem(p_username text, p_password text, p_account_type text, p_accreditation_no text, p_email text)
 RETURNS text
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path = public, extensions
AS $function$
DECLARE
  v_username TEXT := UPPER(TRIM(COALESCE(p_username, '')));
  v_accred TEXT := UPPER(TRIM(COALESCE(p_accreditation_no, '')));
  v_linked_hash TEXT;
  v_ids BIGINT[];
  v_locked TIMESTAMPTZ;
  v_new_count INT;
  v_max_attempts INT := 5;
  v_lockout_minutes INT := 15;
BEGIN
  IF v_username = '' THEN
    RETURN 'Please enter your username (PhilHealth PIN or Employee ID No.).';
  END IF;

  IF position('@' IN v_username) > 0 THEN
    RETURN 'The username must not contain "@".';
  END IF;

  -- Una ang email: kailangang verified (may OTP) bago ang lahat
  IF NOT EXISTS (
    SELECT 1 FROM registration_email_verifications
    WHERE LOWER(email) = LOWER(p_email)
      AND verified_at > NOW() - INTERVAL '2 hours'
  ) THEN
    RETURN 'Please verify your email address first (the verification is valid for 2 hours).';
  END IF;

  IF EXISTS (SELECT 1 FROM users WHERE LOWER(email) = LOWER(p_email) AND status != 'REJECTED') THEN
    RETURN 'This email address is already registered to another account. Please use a different email (each pharmacy account needs its own email), or use "Forgot Password" if this is your account.';
  END IF;

  IF EXISTS (SELECT 1 FROM registration_attempts
             WHERE LOWER(email) = LOWER(p_email) AND attempted_at > NOW() - INTERVAL '10 minutes') THEN
    RETURN 'Please wait a few minutes before trying to register again with this email.';
  END IF;

  IF (SELECT COUNT(*) FROM registration_attempts
      WHERE LOWER(email) = LOWER(p_email) AND attempted_at > NOW() - INTERVAL '24 hours') >= 5 THEN
    RETURN 'Too many registration attempts with this email today. Please try again tomorrow or contact support.';
  END IF;

  IF UPPER(p_account_type) = 'PHARMACY' THEN
    IF EXISTS (
      SELECT 1 FROM users
      WHERE account_type = 'PHARMACY'
        AND _pharmacy_pin(username) = v_username
        AND status != 'REJECTED'
        AND UPPER(accreditation_no) = v_accred
    ) THEN
      RETURN 'This PhilHealth Identification Number (PIN) is already registered for this pharmacy (accreditation no.). If this is your account, please use "Forgot Password" instead.';
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
    -- Dagdag na pharmacy: kasama sa lockout ng login ang maling password
    SELECT array_agg(id), MAX(locked_until) INTO v_ids, v_locked
    FROM users
    WHERE account_type = 'PHARMACY' AND _pharmacy_pin(username) = v_username;

    IF v_locked IS NOT NULL AND v_locked > NOW() THEN
      RETURN 'Too many incorrect password attempts. Please try again in ' ||
             GREATEST(1, CEIL(EXTRACT(EPOCH FROM (v_locked - NOW())) / 60))::INT || ' minute(s).';
    END IF;

    IF v_linked_hash IS DISTINCT FROM crypt(COALESCE(p_password, ''), v_linked_hash) THEN
      SELECT COALESCE(MAX(failed_login_count), 0) + 1 INTO v_new_count FROM users WHERE id = ANY(v_ids);

      UPDATE users
      SET failed_login_count = v_new_count,
          locked_until = CASE
            WHEN v_new_count >= v_max_attempts
            THEN NOW() + (v_lockout_minutes || ' minutes')::INTERVAL
            ELSE locked_until
          END
      WHERE id = ANY(v_ids);

      PERFORM _log_login_event(v_username, 'LOGIN_FAILED',
        'Wrong current password while registering an additional pharmacy (attempt ' || v_new_count || ' of ' || v_max_attempts || ').' ||
        CASE WHEN v_new_count >= v_max_attempts THEN ' Account locked for ' || v_lockout_minutes || ' minutes.' ELSE '' END);

      RETURN 'This PIN already has an EGOS account in another pharmacy. To add this pharmacy, enter your CURRENT EGOS password in the Password field (one password is used for all your pharmacies).';
    END IF;

    IF v_accred = '' THEN
      RETURN 'Please enter the Facility Accreditation No. of the pharmacy you are adding.';
    END IF;

    -- Hindi na kailangang i-check ang username: PIN@ACCRED ang gagamitin kung gamit na ang PIN
    RETURN NULL;
  END IF;

  IF LENGTH(COALESCE(p_password, '')) < 8 THEN
    RETURN 'Password must be at least 8 characters long.';
  END IF;
  IF p_password !~ '[A-Z]' THEN
    RETURN 'Password must contain at least one uppercase letter.';
  END IF;
  IF p_password !~ '[a-z]' THEN
    RETURN 'Password must contain at least one lowercase letter.';
  END IF;
  IF p_password !~ '[0-9]' THEN
    RETURN 'Password must contain at least one number.';
  END IF;

  IF EXISTS (SELECT 1 FROM users WHERE UPPER(username) = v_username AND status != 'REJECTED') THEN
    IF UPPER(p_account_type) = 'STAFF' THEN
      RETURN 'This PhilHealth Employee ID No. is already registered to another account. If this is your account, please use "Forgot Password" instead.';
    END IF;
    RETURN 'This PhilHealth Identification Number (PIN) is already registered to another account. If this is your account, please use "Forgot Password" instead.';
  END IF;

  RETURN NULL;
END;
$function$;
REVOKE ALL ON FUNCTION public._registration_problem(text, text, text, text, text) FROM PUBLIC, anon, authenticated;


-- ---------- 2. Precheck: tinatawag ng page BAGO mag-upload ----------
CREATE OR REPLACE FUNCTION public.precheck_registration(p_username text, p_password text, p_account_type text, p_accreditation_no text, p_email text)
 RETURNS json
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path = public, extensions
AS $function$
DECLARE
  v_problem TEXT;
BEGIN
  v_problem := _registration_problem(p_username, p_password, p_account_type, p_accreditation_no, p_email);
  IF v_problem IS NOT NULL THEN
    RETURN json_build_object('success', false, 'message', v_problem);
  END IF;
  RETURN json_build_object('success', true);
END;
$function$;


-- ---------- 3. register_user: gumagamit na ng parehong helper ----------
CREATE OR REPLACE FUNCTION public.register_user(p_username text, p_password text, p_account_type text, p_facility text, p_branch text, p_accreditation_no text, p_email text, p_attachment_link text, p_philhealth_pin text, p_employee_id_no text)
 RETURNS json
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path = public, extensions
AS $function$
DECLARE
  v_problem TEXT;
  v_role TEXT;
  v_username TEXT := UPPER(TRIM(COALESCE(p_username, '')));
  v_accred TEXT := UPPER(TRIM(COALESCE(p_accreditation_no, '')));
  v_linked_hash TEXT;
  v_linked_list TEXT;
BEGIN
  v_problem := _registration_problem(p_username, p_password, p_account_type, p_accreditation_no, p_email);
  IF v_problem IS NOT NULL THEN
    RETURN json_build_object('success', false, 'message', v_problem);
  END IF;

  INSERT INTO registration_attempts (email) VALUES (p_email);

  -- May account na ba ang PIN sa ibang pharmacy? (na-verify na ang password sa helper)
  IF UPPER(p_account_type) = 'PHARMACY' THEN
    SELECT password INTO v_linked_hash
    FROM users
    WHERE account_type = 'PHARMACY'
      AND _pharmacy_pin(username) = v_username
      AND status != 'REJECTED'
    ORDER BY (status = 'APPROVED') DESC, id
    LIMIT 1;
  END IF;

  -- Dagdag na pharmacy: PIN@ACCRED ang username kung gamit na ang PIN mismo
  IF v_linked_hash IS NOT NULL AND EXISTS (
    SELECT 1 FROM users WHERE UPPER(username) = v_username AND status != 'REJECTED'
  ) THEN
    v_username := v_username || '@' || v_accred;
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

COMMIT;

-- ---------- PAG-CHECK (patakbuhin pagkatapos) ----------
-- Dapat 2 row: precheck_registration (anon_exec = true) at _registration_problem (anon_exec = false)
--   SELECT proname, has_function_privilege('anon', p.oid, 'EXECUTE') AS anon_exec
--   FROM pg_proc p WHERE proname IN ('precheck_registration', '_registration_problem');
