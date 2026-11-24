-- =====================================================================
-- ROLLBACK ng 2026-11-24_17_same_pin_multiple_pharmacies.sql
-- Ibinabalik ang dating login, registration at approval functions, at
-- tinatanggal ang password-sync trigger.
--
-- PAALALA: hindi binubura ang mga account na PIN@ACCREDITATION na nagawa na.
--   Makakapag-login pa rin sila kung buong username (PIN@ACCRED) ang ita-type,
--   pero hindi na sabay ang password nila sa unang account.
-- =====================================================================

BEGIN;

DROP TRIGGER IF EXISTS users_sync_linked_pharmacy_password ON public.users;
DROP FUNCTION IF EXISTS public._sync_linked_pharmacy_password();

DROP FUNCTION IF EXISTS public.check_staff_login(text, text, text);

CREATE OR REPLACE FUNCTION public.check_staff_login(input_username text, input_password text)
 RETURNS json
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path = public, extensions
AS $function$
DECLARE
  user_record RECORD;
  v_max_attempts INT := 5;
  v_lockout_minutes INT := 15;
  v_new_count INT;
  v_token TEXT;
BEGIN
  SELECT * INTO user_record
  FROM users
  WHERE UPPER(username) = UPPER(input_username);

  IF user_record IS NULL THEN
    PERFORM _log_login_event(input_username, 'LOGIN_FAILED', 'Unknown username.');
    RETURN json_build_object('success', false, 'message', 'Invalid credentials.');
  END IF;

  -- I-check kung naka-lock pa ang account
  IF user_record.locked_until IS NOT NULL AND user_record.locked_until > NOW() THEN
    PERFORM _log_login_event(user_record.username, 'LOGIN_LOCKED', 'Attempt while account is locked.');
    RETURN json_build_object(
      'success', false,
      'message', 'Too many failed login attempts. Please try again in ' ||
                 GREATEST(1, CEIL(EXTRACT(EPOCH FROM (user_record.locked_until - NOW())) / 60))::INT || ' minute(s).'
    );
  END IF;

  -- I-verify ang password
  IF user_record.password != crypt(input_password, user_record.password) THEN
    v_new_count := COALESCE(user_record.failed_login_count, 0) + 1;

    UPDATE users
    SET failed_login_count = v_new_count,
        locked_until = CASE
          WHEN v_new_count >= v_max_attempts
          THEN NOW() + (v_lockout_minutes || ' minutes')::INTERVAL
          ELSE locked_until
        END
    WHERE id = user_record.id;

    PERFORM _log_login_event(user_record.username, 'LOGIN_FAILED',
      'Wrong password (attempt ' || v_new_count || ' of ' || v_max_attempts || ').' ||
      CASE WHEN v_new_count >= v_max_attempts THEN ' Account locked for ' || v_lockout_minutes || ' minutes.' ELSE '' END);

    RETURN json_build_object('success', false, 'message', 'Invalid credentials.');
  END IF;

  -- Tamang password: i-reset ang counter
  UPDATE users SET failed_login_count = 0, locked_until = NULL WHERE id = user_record.id;

  IF user_record.status = 'PENDING' THEN
    PERFORM _log_login_event(user_record.username, 'LOGIN_BLOCKED', 'Account still PENDING.');
    RETURN json_build_object('success', false, 'message', 'Your account is still awaiting admin approval.');
  END IF;

  IF user_record.status = 'REJECTED' THEN
    PERFORM _log_login_event(user_record.username, 'LOGIN_BLOCKED', 'Account REJECTED.');
    RETURN json_build_object('success', false, 'message', 'Your registration was declined. Please contact the admin.');
  END IF;

  IF user_record.status = 'DEACTIVATED' THEN
    PERFORM _log_login_event(user_record.username, 'LOGIN_BLOCKED', 'Account DEACTIVATED.');
    RETURN json_build_object('success', false, 'message', 'Your account has been deactivated. Please contact your Pharmacy Admin.');
  END IF;

  -- BAGO: gumawa ng session token (ang hash lang ang ise-save)
  DELETE FROM sessions
  WHERE user_id = user_record.id
    AND (expires_at < NOW() OR revoked_at IS NOT NULL);

  v_token := encode(gen_random_bytes(32), 'hex');

  INSERT INTO sessions (token_hash, user_id, expires_at)
  VALUES (encode(digest(v_token, 'sha256'), 'hex'), user_record.id, NOW() + INTERVAL '12 hours');

  PERFORM _log_login_event(user_record.username, 'LOGIN_SUCCESS', NULL);

  RETURN json_build_object(
    'success', true,
    'token', v_token,
    'role', user_record.role,
    'facility', user_record.facility,
    'branch', user_record.branch,
    'idNo', user_record.id_no,
    'account_type', user_record.account_type,
    'accreditation_no', user_record.accreditation_no
  );
END;
$function$;

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
BEGIN
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

  -- BAGO: ang server na mismo ang nagche-check na na-verify ang email (dati sa browser lang)
  IF NOT EXISTS (
    SELECT 1 FROM registration_email_verifications
    WHERE LOWER(email) = LOWER(p_email)
      AND verified_at > NOW() - INTERVAL '2 hours'
  ) THEN
    RETURN json_build_object('success', false, 'message', 'Please verify your email address first (the verification is valid for 2 hours).');
  END IF;

  -- hindi kasama ang REJECTED (declined) accounts sa email uniqueness check
  -- para makapag-register ulit ang mga na-decline gamit ang parehong email
  SELECT COUNT(*) INTO v_existing_email
  FROM users
  WHERE LOWER(email) = LOWER(p_email)
    AND status != 'REJECTED';

  IF v_existing_email > 0 THEN
    RETURN json_build_object('success', false, 'message', 'This email address is already registered to another account. Please use a different email, or use "Forgot Password" if this is your account.');
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

  -- hindi rin kasama ang REJECTED accounts sa username/PIN/Employee ID uniqueness check
  SELECT COUNT(*) INTO v_existing
  FROM users
  WHERE UPPER(username) = UPPER(p_username)
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
  SET password = crypt(p_password, gen_salt('bf')),
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
  WHERE UPPER(username) = UPPER(p_username)
    AND status = 'REJECTED';

  IF FOUND THEN
    PERFORM log_account_audit(UPPER(p_username), 'RE_REGISTERED', UPPER(p_username), UPPER(p_branch), 'Declined account registered again with a new password and details.');
  ELSE
    BEGIN
      INSERT INTO users (username, password, role, facility, branch, account_type, status, accreditation_no, email, attachment_link, philhealth_pin, employee_id_no)
      VALUES (UPPER(p_username), crypt(p_password, gen_salt('bf')), v_role, UPPER(p_facility), UPPER(p_branch), p_account_type, 'PENDING', UPPER(p_accreditation_no), p_email, p_attachment_link, p_philhealth_pin, p_employee_id_no);
    EXCEPTION WHEN unique_violation THEN
      -- hal. sabay na dalawang submit: malinaw na mensahe sa halip na error ng database
      RETURN json_build_object('success', false, 'message', 'This ID or email is already registered to another account. If this is your account, please use "Forgot Password" instead.');
    END;
  END IF;

  -- BAGO: gamit na ang verification (hindi na puwedeng gamitin ulit)
  DELETE FROM registration_email_verifications WHERE LOWER(email) = LOWER(p_email);

  RETURN json_build_object('success', true);
END;
$function$;

CREATE OR REPLACE FUNCTION public.get_pending_users(p_branch text DEFAULT NULL::text)
 RETURNS json
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path = public, extensions
AS $function$
DECLARE
  result JSON;
  v_caller public.users;
BEGIN
  -- BAGO (2b): kapag may session token, ang server ang nagtatakda ng branch
  v_caller := _current_caller(ARRAY['ADMIN', 'BRANCH_ADMIN']);
  IF v_caller.id IS NOT NULL THEN
    p_branch := CASE WHEN v_caller.role = 'ADMIN' THEN NULL ELSE COALESCE(v_caller.branch, '__NONE__') END;
  END IF;

  SELECT json_agg(row_to_json(u)) INTO result
  FROM (
    SELECT username, account_type, facility, branch, created_at, attachment_link
    FROM users u
    WHERE status = 'PENDING'
      AND (p_branch IS NULL OR p_branch = '' OR UPPER(branch) = UPPER(p_branch))
      AND (
        account_type != 'PHARMACY'
        OR NOT EXISTS (
          SELECT 1 FROM users pa
          WHERE pa.accreditation_no = u.accreditation_no
            AND pa.role = 'PHARMACY_ADMIN'
            AND pa.status = 'APPROVED'
        )
      )
    ORDER BY created_at
  ) u;

  RETURN COALESCE(result, '[]'::json);
END;
$function$;

CREATE OR REPLACE FUNCTION public.get_pending_pharmacy_staff(p_accreditation_no text)
 RETURNS json
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path = public, extensions
AS $function$
DECLARE
  result JSON;
  v_caller public.users;
BEGIN
  -- BAGO (2b): kapag may session token, sariling accreditation lang
  v_caller := _current_caller(ARRAY['PHARMACY_ADMIN']);
  IF v_caller.id IS NOT NULL THEN
    p_accreditation_no := COALESCE(v_caller.accreditation_no, '__NONE__');
  END IF;

  SELECT json_agg(row_to_json(u)) INTO result
  FROM (
    SELECT username, facility, branch, created_at, attachment_link
    FROM users
    WHERE status = 'PENDING'
      AND account_type = 'PHARMACY'
      AND accreditation_no = p_accreditation_no
    ORDER BY created_at
  ) u;

  RETURN COALESCE(result, '[]'::json);
END;
$function$;

CREATE OR REPLACE FUNCTION public.approve_pharmacy_staff(p_username text, p_decision text, p_decline_reason text, p_accreditation_no text, p_performed_by text DEFAULT NULL::text)
 RETURNS json
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path = public, extensions
AS $function$
DECLARE
  v_id INT;
  v_new_id_no TEXT;
  v_target_accred TEXT;
  v_branch TEXT;
  v_caller public.users;
BEGIN
  -- BAGO (2b): kapag may session token, server ang nagtatakda ng performer + accreditation
  v_caller := _current_caller(ARRAY['PHARMACY_ADMIN']);
  IF v_caller.id IS NOT NULL THEN
    p_performed_by := v_caller.username;
    p_accreditation_no := COALESCE(v_caller.accreditation_no, '__NONE__');
  END IF;

  SELECT id, accreditation_no, branch INTO v_id, v_target_accred, v_branch
  FROM users WHERE UPPER(username) = UPPER(p_username);

  IF v_target_accred IS DISTINCT FROM p_accreditation_no THEN
    RETURN json_build_object('success', false, 'message', 'Not authorized for this account.');
  END IF;

  IF UPPER(p_decision) = 'APPROVED' THEN
    v_new_id_no := 'EOGS-' || LPAD(v_id::TEXT, 5, '0');
    UPDATE users SET status = 'APPROVED', id_no = v_new_id_no, role = 'USER'
    WHERE UPPER(username) = UPPER(p_username);

    IF p_performed_by IS NOT NULL THEN
      PERFORM log_account_audit(p_username, 'APPROVED', p_performed_by, v_branch, 'Approved by Pharmacy Admin.');
    END IF;
  ELSE
    UPDATE users SET status = UPPER(p_decision), decline_reason = p_decline_reason
    WHERE UPPER(username) = UPPER(p_username);

    IF p_performed_by IS NOT NULL THEN
      PERFORM log_account_audit(p_username, UPPER(p_decision), p_performed_by, v_branch, p_decline_reason);
    END IF;
  END IF;

  RETURN json_build_object('success', true);
END;
$function$;

CREATE OR REPLACE FUNCTION public.pharmacy_admin_reset_password(p_username text, p_accreditation_no text, p_new_password text, p_performed_by text DEFAULT NULL::text)
 RETURNS json
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path = public, extensions
AS $function$
DECLARE
  v_target_accred TEXT;
  v_branch TEXT;
  v_caller public.users;
BEGIN
  -- BAGO (2b): kapag may session token, server ang nagtatakda ng performer + accreditation
  v_caller := _current_caller(ARRAY['PHARMACY_ADMIN']);
  IF v_caller.id IS NOT NULL THEN
    p_performed_by := v_caller.username;
    p_accreditation_no := COALESCE(v_caller.accreditation_no, '__NONE__');
  END IF;

  SELECT accreditation_no, branch INTO v_target_accred, v_branch FROM users WHERE UPPER(username) = UPPER(p_username);

  IF v_target_accred IS DISTINCT FROM p_accreditation_no THEN
    RETURN json_build_object('success', false, 'message', 'Not authorized for this account.');
  END IF;

  UPDATE users SET password = crypt(p_new_password, gen_salt('bf')) WHERE UPPER(username) = UPPER(p_username);

  IF p_performed_by IS NOT NULL THEN
    PERFORM log_account_audit(p_username, 'PASSWORD_RESET', p_performed_by, v_branch, 'Password reset by Pharmacy Admin.');
  END IF;

  RETURN json_build_object('success', true);
END;
$function$;

DROP FUNCTION IF EXISTS public._pharmacy_pin(TEXT);

COMMIT;
