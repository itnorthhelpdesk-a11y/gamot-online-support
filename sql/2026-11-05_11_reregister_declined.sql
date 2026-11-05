-- =====================================================================
-- Ayusin ang "users_username_unique" error kapag nagre-register ulit ang
-- declined na account. Tanging ang INSERT ang nagbago sa register_user.
-- Lahat ng pagbabago sa password ay naka-log sa account_audit_trail.
-- =====================================================================

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
