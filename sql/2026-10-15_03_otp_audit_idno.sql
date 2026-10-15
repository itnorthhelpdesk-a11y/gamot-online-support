-- =====================================================================
-- EGOS Hakbang 3: OTP limits, verified email sa registration,
--                 before/after sa audit, at encoded_by = EOGS ID
-- Petsa: 2026-10-15
--
-- LIGTAS PATAKBUHIN KAHIT KAILAN: parehong parameters ang lahat ng
-- function, at gumagana pa rin ito sa kasalukuyang live index.html.
--
-- 1. FORGOT PASSWORD (reset_password_with_otp)
--    - Max 5 maling code; pagkatapos ay mabubura ang code (hihingi ng bago)
--    - Ipinapatupad na ang password rules (8+ chars, upper, lower, number)
--    - Ina-unlock ang account, nilo-logout ang lahat ng session ng user
--    - Itinatala sa account_audit_trail (PASSWORD_RESET_SELF)
-- 2. REGISTRATION
--    - verify_registration_otp: max 5 maling code; minamarkahan ang email
--      bilang verified (verified_at) sa halip na burahin
--    - register_user: TATANGGI kapag hindi na-verify ang email sa loob
--      ng nakaraang 2 oras (dati, sa browser lang ito chine-check)
-- 3. AUDIT BEFORE/AFTER
--    - edit_deficiency_record, update_tracker_fields, update_staff_email,
--      update_staff_email_by_admin: nakasulat na kung ano ang binago,
--      hal. "Contact: 09171234567 -> 09181234567"
-- 4. encode_deficiency: encoded_by = EOGS ID ng encoder (hal. EOGS-00012);
--    username lang kung walang EOGS ID
--
-- ROLLBACK: 2026-10-15_03_rollback.sql
-- =====================================================================

BEGIN;

-- ---------- Bagong columns ----------
ALTER TABLE public.password_reset_requests
  ADD COLUMN IF NOT EXISTS attempts INT NOT NULL DEFAULT 0;
ALTER TABLE public.registration_email_verifications
  ADD COLUMN IF NOT EXISTS attempts INT NOT NULL DEFAULT 0,
  ADD COLUMN IF NOT EXISTS verified_at TIMESTAMPTZ;

-- ---------- Helper: "Label: luma -> bago" kapag may binago, NULL kapag wala ----------
CREATE OR REPLACE FUNCTION public._audit_change(p_label TEXT, p_old TEXT, p_new TEXT)
 RETURNS TEXT
 LANGUAGE sql
 IMMUTABLE
AS $function$
  SELECT CASE
    WHEN p_old IS NOT DISTINCT FROM p_new THEN NULL
    ELSE p_label || ': ' || COALESCE(NULLIF(p_old, ''), '(blank)') || ' -> ' || COALESCE(NULLIF(p_new, ''), '(blank)')
  END;
$function$;
REVOKE EXECUTE ON FUNCTION public._audit_change(TEXT, TEXT, TEXT) FROM PUBLIC, anon, authenticated;


-- =====================================================================
-- 1. FORGOT PASSWORD
-- =====================================================================
CREATE OR REPLACE FUNCTION public.reset_password_with_otp(p_username text, p_otp text, p_new_password text)
 RETURNS json
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path = public, extensions
AS $function$
DECLARE
  v_req RECORD;
  v_user RECORD;
  v_max_attempts INT := 5;
BEGIN
  -- Ang pinakabagong code lang ang tinatanggap
  SELECT * INTO v_req
  FROM password_reset_requests
  WHERE UPPER(username) = UPPER(p_username)
    AND expires_at > NOW()
  ORDER BY created_at DESC
  LIMIT 1;

  IF NOT FOUND THEN
    RETURN json_build_object('success', false, 'message', 'Invalid or expired code.');
  END IF;

  IF v_req.otp IS DISTINCT FROM p_otp THEN
    UPDATE password_reset_requests SET attempts = attempts + 1 WHERE id = v_req.id;

    IF v_req.attempts + 1 >= v_max_attempts THEN
      DELETE FROM password_reset_requests WHERE UPPER(username) = UPPER(p_username);
      RETURN json_build_object('success', false, 'message', 'Too many incorrect attempts. Please request a new code.');
    END IF;

    RETURN json_build_object('success', false, 'message', 'Invalid or expired code.');
  END IF;

  -- Parehong password rules ng registration (hindi pa nauubos ang code kapag mali ito)
  IF LENGTH(COALESCE(p_new_password, '')) < 8
     OR p_new_password !~ '[A-Z]' OR p_new_password !~ '[a-z]' OR p_new_password !~ '[0-9]' THEN
    RETURN json_build_object('success', false, 'message', 'Password must be at least 8 characters and include an uppercase letter, a lowercase letter, and a number.');
  END IF;

  SELECT id, username, branch INTO v_user FROM users WHERE UPPER(username) = UPPER(p_username);

  IF NOT FOUND THEN
    RETURN json_build_object('success', false, 'message', 'Invalid or expired code.');
  END IF;

  UPDATE users
  SET password = crypt(p_new_password, gen_salt('bf')),
      failed_login_count = 0,
      locked_until = NULL
  WHERE id = v_user.id;

  DELETE FROM password_reset_requests WHERE UPPER(username) = UPPER(p_username);

  -- I-logout ang lahat ng bukas na session ng user
  UPDATE sessions SET revoked_at = NOW() WHERE user_id = v_user.id AND revoked_at IS NULL;

  PERFORM log_account_audit(v_user.username, 'PASSWORD_RESET_SELF', v_user.username, v_user.branch,
    'Password reset by the account holder using an emailed code.');

  RETURN json_build_object('success', true);
END;
$function$;


-- =====================================================================
-- 2. REGISTRATION
-- =====================================================================
CREATE OR REPLACE FUNCTION public.verify_registration_otp(p_email text, p_otp text)
 RETURNS json
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path = public, extensions
AS $function$
DECLARE
  v_req RECORD;
  v_max_attempts INT := 5;
BEGIN
  SELECT * INTO v_req
  FROM registration_email_verifications
  WHERE LOWER(email) = LOWER(p_email)
    AND expires_at > NOW()
    AND verified_at IS NULL
  ORDER BY created_at DESC
  LIMIT 1;

  IF NOT FOUND THEN
    RETURN json_build_object('success', false, 'message', 'Invalid or expired code.');
  END IF;

  IF v_req.otp IS DISTINCT FROM p_otp THEN
    UPDATE registration_email_verifications SET attempts = attempts + 1 WHERE id = v_req.id;

    IF v_req.attempts + 1 >= v_max_attempts THEN
      UPDATE registration_email_verifications SET expires_at = NOW()
      WHERE LOWER(email) = LOWER(p_email) AND verified_at IS NULL;
      RETURN json_build_object('success', false, 'message', 'Too many incorrect attempts. Please request a new code.');
    END IF;

    RETURN json_build_object('success', false, 'message', 'Invalid or expired code.');
  END IF;

  -- BAGO: markahan bilang verified (chine-check ito ng register_user)
  UPDATE registration_email_verifications SET verified_at = NOW() WHERE id = v_req.id;

  RETURN json_build_object('success', true);
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

  INSERT INTO users (username, password, role, facility, branch, account_type, status, accreditation_no, email, attachment_link, philhealth_pin, employee_id_no)
  VALUES (UPPER(p_username), crypt(p_password, gen_salt('bf')), v_role, UPPER(p_facility), UPPER(p_branch), p_account_type, 'PENDING', UPPER(p_accreditation_no), p_email, p_attachment_link, p_philhealth_pin, p_employee_id_no);

  -- BAGO: gamit na ang verification (hindi na puwedeng gamitin ulit)
  DELETE FROM registration_email_verifications WHERE LOWER(email) = LOWER(p_email);

  RETURN json_build_object('success', true);
END;
$function$;


-- =====================================================================
-- 3. AUDIT BEFORE/AFTER
-- =====================================================================
CREATE OR REPLACE FUNCTION public.edit_deficiency_record(p_gatn_no text, p_requesting_branch text, p_gacn_no text, p_issue_category text, p_specific_issue text, p_facility text, p_facility_accreditation_no text, p_claimant_last_name text, p_claimant_first_name text, p_claimant_contact text, p_performed_by_username text)
 RETURNS json
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path = public, extensions
AS $function$
DECLARE
  v_old RECORD;
  v_resolution TEXT;
  v_changes TEXT;
  v_caller public.users;
BEGIN
  -- kapag may session token, server ang nagtatakda ng performer + branch
  v_caller := _current_caller(ARRAY['ADMIN', 'BRANCH_ADMIN', 'STAFF', 'BAS']);
  IF v_caller.id IS NOT NULL THEN
    p_performed_by_username := v_caller.username;
    p_requesting_branch := CASE WHEN v_caller.role = 'ADMIN' THEN NULL ELSE COALESCE(v_caller.branch, '__NONE__') END;
  END IF;

  SELECT * INTO v_old FROM deficiency_records WHERE gatn_no = UPPER(p_gatn_no);

  IF NOT FOUND THEN
    RETURN json_build_object('success', false, 'message', 'Record not found.');
  END IF;

  IF p_requesting_branch IS NOT NULL AND p_requesting_branch != ''
     AND UPPER(v_old.pro_region) IS DISTINCT FROM UPPER(p_requesting_branch) THEN
    RETURN json_build_object('success', false, 'message', 'Not authorized for this record.');
  END IF;

  SELECT required_resolution INTO v_resolution
  FROM deficiency_resolution_guide
  WHERE issue_category = p_issue_category AND specific_issue = p_specific_issue
  LIMIT 1;

  UPDATE deficiency_records
  SET gacn_no = UPPER(p_gacn_no),
      issue_category = p_issue_category,
      specific_issue = p_specific_issue,
      required_resolution = COALESCE(v_resolution, required_resolution),
      facility = UPPER(p_facility),
      facility_accreditation_no = UPPER(p_facility_accreditation_no),
      claimant_last_name = UPPER(p_claimant_last_name),
      claimant_first_name = UPPER(p_claimant_first_name),
      claimant_contact = p_claimant_contact
  WHERE gatn_no = UPPER(p_gatn_no);

  -- BAGO: itala kung ano mismo ang binago (luma -> bago)
  v_changes := concat_ws('; ',
    _audit_change('GACN', v_old.gacn_no, UPPER(p_gacn_no)),
    _audit_change('Issue Category', v_old.issue_category, p_issue_category),
    _audit_change('Specific Issue', v_old.specific_issue, p_specific_issue),
    _audit_change('Facility', v_old.facility, UPPER(p_facility)),
    _audit_change('Accreditation No.', v_old.facility_accreditation_no, UPPER(p_facility_accreditation_no)),
    _audit_change('Claimant Last Name', v_old.claimant_last_name, UPPER(p_claimant_last_name)),
    _audit_change('Claimant First Name', v_old.claimant_first_name, UPPER(p_claimant_first_name)),
    _audit_change('Contact', v_old.claimant_contact, p_claimant_contact)
  );

  PERFORM log_audit_trail(UPPER(p_gatn_no), 'EDIT', p_performed_by_username, v_old.pro_region,
    'Record fields updated: ' || COALESCE(NULLIF(v_changes, ''), 'no changes.'));

  RETURN json_build_object('success', true);
END;
$function$;


CREATE OR REPLACE FUNCTION public.update_tracker_fields(p_gatn_no text, p_requesting_branch text, p_remarks text, p_action_taken text, p_date_processed date DEFAULT NULL::date, p_performed_by_username text DEFAULT NULL::text)
 RETURNS json
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path = public, extensions
AS $function$
DECLARE
  v_old RECORD;
  v_changes TEXT;
  v_caller public.users;
BEGIN
  -- kapag may session token, server ang nagtatakda ng performer + branch
  v_caller := _current_caller(ARRAY['ADMIN', 'BRANCH_ADMIN', 'STAFF', 'BAS']);
  IF v_caller.id IS NOT NULL THEN
    p_performed_by_username := v_caller.username;
    p_requesting_branch := CASE WHEN v_caller.role = 'ADMIN' THEN NULL ELSE COALESCE(v_caller.branch, '__NONE__') END;
  END IF;

  SELECT * INTO v_old FROM deficiency_records WHERE gatn_no = UPPER(p_gatn_no);

  IF NOT FOUND THEN
    RETURN json_build_object('success', false, 'message', 'Record not found.');
  END IF;

  IF p_requesting_branch IS NOT NULL AND p_requesting_branch != ''
     AND UPPER(v_old.pro_region) IS DISTINCT FROM UPPER(p_requesting_branch) THEN
    RETURN json_build_object('success', false, 'message', 'Not authorized for this record.');
  END IF;

  UPDATE deficiency_records
  SET tracker_remarks = p_remarks,
      tracker_action_taken = p_action_taken,
      tracker_date_processed = p_date_processed
  WHERE gatn_no = UPPER(p_gatn_no);

  -- BAGO: itala kung ano mismo ang binago (luma -> bago)
  v_changes := concat_ws('; ',
    _audit_change('Remarks', v_old.tracker_remarks, p_remarks),
    _audit_change('Action Taken', v_old.tracker_action_taken, p_action_taken),
    _audit_change('Date Processed', v_old.tracker_date_processed::TEXT, p_date_processed::TEXT)
  );

  IF p_performed_by_username IS NOT NULL THEN
    PERFORM log_audit_trail(UPPER(p_gatn_no), 'TRACKER_UPDATE', p_performed_by_username, v_old.pro_region,
      'GAMOT Tracker fields updated: ' || COALESCE(NULLIF(v_changes, ''), 'no changes.'));
  END IF;

  RETURN json_build_object('success', true);
END;
$function$;


CREATE OR REPLACE FUNCTION public.update_staff_email(p_username text, p_accreditation_no text, p_new_email text, p_performed_by text DEFAULT NULL::text)
 RETURNS json
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path = public, extensions
AS $function$
DECLARE
  v_target_accred TEXT;
  v_branch TEXT;
  v_old_email TEXT;
  v_caller public.users;
BEGIN
  -- kapag may session token, server ang nagtatakda ng performer + accreditation
  v_caller := _current_caller(ARRAY['PHARMACY_ADMIN']);
  IF v_caller.id IS NOT NULL THEN
    p_performed_by := v_caller.username;
    p_accreditation_no := COALESCE(v_caller.accreditation_no, '__NONE__');
  END IF;

  SELECT accreditation_no, branch, email INTO v_target_accred, v_branch, v_old_email
  FROM users WHERE UPPER(username) = UPPER(p_username);

  IF v_target_accred IS DISTINCT FROM p_accreditation_no THEN
    RETURN json_build_object('success', false, 'message', 'Not authorized for this account.');
  END IF;

  UPDATE users SET email = p_new_email WHERE UPPER(username) = UPPER(p_username);

  IF p_performed_by IS NOT NULL THEN
    PERFORM log_account_audit(p_username, 'EMAIL_UPDATED', p_performed_by, v_branch,
      'Email updated by Pharmacy Admin: ' || COALESCE(_audit_change('Email', v_old_email, p_new_email), 'no change.'));
  END IF;

  RETURN json_build_object('success', true);
END;
$function$;


CREATE OR REPLACE FUNCTION public.update_staff_email_by_admin(p_username text, p_requesting_branch text, p_new_email text, p_performed_by text DEFAULT NULL::text)
 RETURNS json
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path = public, extensions
AS $function$
DECLARE
  v_target_branch TEXT;
  v_old_email TEXT;
  v_caller public.users;
BEGIN
  -- kapag may session token, server ang nagtatakda ng performer + branch
  v_caller := _current_caller(ARRAY['ADMIN', 'BRANCH_ADMIN']);
  IF v_caller.id IS NOT NULL THEN
    p_performed_by := v_caller.username;
    p_requesting_branch := CASE WHEN v_caller.role = 'ADMIN' THEN NULL ELSE COALESCE(v_caller.branch, '__NONE__') END;
  END IF;

  SELECT branch, email INTO v_target_branch, v_old_email FROM users WHERE UPPER(username) = UPPER(p_username);

  IF p_requesting_branch IS NOT NULL AND p_requesting_branch != ''
     AND UPPER(v_target_branch) IS DISTINCT FROM UPPER(p_requesting_branch) THEN
    RETURN json_build_object('success', false, 'message', 'Not authorized for this account.');
  END IF;

  UPDATE users SET email = p_new_email WHERE UPPER(username) = UPPER(p_username);

  IF p_performed_by IS NOT NULL THEN
    PERFORM log_account_audit(p_username, 'EMAIL_UPDATED', p_performed_by, v_target_branch,
      'Email updated by Admin: ' || COALESCE(_audit_change('Email', v_old_email, p_new_email), 'no change.'));
  END IF;

  RETURN json_build_object('success', true);
END;
$function$;


-- =====================================================================
-- 4. encode_deficiency: encoded_by = EOGS ID
-- =====================================================================
CREATE OR REPLACE FUNCTION public.encode_deficiency(p_pro_region text, p_gacn_no text, p_gatn_no text, p_issue_category text, p_specific_issue text, p_facility text, p_facility_accreditation_no text, p_claimant_last_name text, p_claimant_first_name text, p_claimant_contact text, p_encoded_by text, p_performed_by_username text, p_claim_amount numeric DEFAULT NULL::numeric, p_send_to_pharmacy boolean DEFAULT true)
 RETURNS json
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path = public, extensions
AS $function$
DECLARE
  v_resolution TEXT;
  v_existing_count INT;
  v_clean_accred TEXT;
  v_branch_code TEXT;
  v_status TEXT;
  v_rtf_date TIMESTAMPTZ;
  v_deadline TIMESTAMPTZ;
  v_encoder_department TEXT;
  v_effective_send BOOLEAN;
  v_caller public.users;
BEGIN
  -- kapag may session token, server ang nagtatakda ng encoder at PRO Region
  v_caller := _current_caller(ARRAY['ADMIN', 'BRANCH_ADMIN', 'STAFF', 'BAS']);
  IF v_caller.id IS NOT NULL THEN
    p_performed_by_username := v_caller.username;
    -- BAGO: EOGS ID ng encoder (username lang kung wala)
    p_encoded_by := COALESCE(NULLIF(v_caller.id_no, ''), v_caller.username);
    IF v_caller.role <> 'ADMIN' THEN
      p_pro_region := COALESCE(v_caller.branch, '__NONE__');
    END IF;
  END IF;

  SELECT COUNT(*) INTO v_existing_count FROM deficiency_records WHERE gatn_no = p_gatn_no;
  IF v_existing_count > 0 THEN
    RETURN json_build_object('success', false, 'message', 'GATN already exists in the system.');
  END IF;

  v_clean_accred := UPPER(TRIM(p_facility_accreditation_no));
  v_branch_code := CASE UPPER(p_pro_region)
    WHEN 'PRONCR NORTH' THEN '91'
    WHEN 'PRONCR SOUTH' THEN '92'
    WHEN 'PRONCR CENTRAL' THEN '93'
    ELSE NULL
  END;

  IF v_branch_code IS NULL
     OR NOT (v_clean_accred LIKE ('P' || v_branch_code || '%') OR v_clean_accred LIKE ('H' || v_branch_code || '%')) THEN
    RETURN json_build_object('success', false, 'message', 'This Facility Accreditation No. (' || v_clean_accred || ') does not match your branch (' || p_pro_region || '). Please verify the accreditation number.');
  END IF;

  SELECT required_resolution INTO v_resolution
  FROM deficiency_resolution_guide
  WHERE issue_category = p_issue_category AND specific_issue = p_specific_issue
  LIMIT 1;

  IF NOT FOUND THEN
    v_resolution := 'No matching resolution found. Please consult PMT-Claims.';
  END IF;

  SELECT UPPER(facility) INTO v_encoder_department
  FROM users
  WHERE UPPER(username) = UPPER(p_performed_by_username);

  v_effective_send := p_send_to_pharmacy;
  IF v_encoder_department = 'ACCOUNTING' THEN
    v_effective_send := FALSE;
  END IF;

  IF v_effective_send THEN
    v_status := 'RTF';
    v_rtf_date := NOW();
    v_deadline := NOW() + INTERVAL '60 days';
  ELSE
    v_status := 'PROCESSING';
    v_rtf_date := NULL;
    v_deadline := NULL;
  END IF;

  INSERT INTO deficiency_records (
    pro_region, gacn_no, gatn_no, issue_category, specific_issue,
    required_resolution, facility, claimant_last_name, claimant_first_name,
    claimant_email, claimant_contact, status, rtf_date, compliance_deadline,
    encoded_by, facility_accreditation_no, claim_amount
  ) VALUES (
    UPPER(p_pro_region), UPPER(p_gacn_no), UPPER(p_gatn_no), p_issue_category, p_specific_issue,
    v_resolution, UPPER(p_facility), UPPER(p_claimant_last_name), UPPER(p_claimant_first_name),
    LOWER(''), p_claimant_contact, v_status, v_rtf_date, v_deadline,
    UPPER(p_encoded_by), v_clean_accred, p_claim_amount
  );

  PERFORM log_audit_trail(UPPER(p_gatn_no), 'ENCODE', p_performed_by_username, UPPER(p_pro_region),
    CASE WHEN v_effective_send THEN 'New deficiency record created and sent to pharmacy (RTF).'
         ELSE 'New deficiency record created for internal tracking only (PROCESSING).' END);

  RETURN json_build_object('success', true, 'resolution', COALESCE(v_resolution, 'No specific action indicated.'), 'status', v_status);
END;
$function$;

COMMIT;
