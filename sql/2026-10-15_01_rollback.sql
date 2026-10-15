-- =====================================================================
-- ROLLBACK para sa 2026-10-15_01_drop_legacy_functions.sql
-- Patakbuhin LAMANG kung may nasira pagkatapos ng Hakbang 1.
-- BABALA: ibinabalik nito ang mga lumang functions, kasama ang security problems nila.
-- Kinuha ang code mula sa live database noong 2026-10-15 (pg_get_functiondef).
-- =====================================================================

BEGIN;

-- ----- admin_reset_password(p_username text, p_requesting_branch text, p_new_password text)
CREATE OR REPLACE FUNCTION public.admin_reset_password(p_username text, p_requesting_branch text, p_new_password text)
 RETURNS json
 LANGUAGE plpgsql
 SECURITY DEFINER
AS $function$
DECLARE
  v_target_branch TEXT;
BEGIN
  SELECT branch INTO v_target_branch FROM users WHERE UPPER(username) = UPPER(p_username);

  IF v_target_branch IS NULL THEN
    RETURN json_build_object('success', false, 'message', 'Account not found.');
  END IF;

  IF p_requesting_branch IS NOT NULL AND p_requesting_branch != ''
     AND UPPER(v_target_branch) IS DISTINCT FROM UPPER(p_requesting_branch) THEN
    RETURN json_build_object('success', false, 'message', 'Not authorized for this account.');
  END IF;

  UPDATE users SET password = crypt(p_new_password, gen_salt('bf')) WHERE UPPER(username) = UPPER(p_username);

  RETURN json_build_object('success', true);
END;
$function$;

-- ----- approve_pharmacy_staff(p_username text, p_decision text, p_decline_reason text, p_accreditation_no text)
CREATE OR REPLACE FUNCTION public.approve_pharmacy_staff(p_username text, p_decision text, p_decline_reason text, p_accreditation_no text)
 RETURNS json
 LANGUAGE plpgsql
 SECURITY DEFINER
AS $function$
DECLARE
  v_id INT;
  v_new_id_no TEXT;
  v_target_accred TEXT;
BEGIN
  SELECT id, accreditation_no INTO v_id, v_target_accred
  FROM users WHERE UPPER(username) = UPPER(p_username);

  -- Security check: kaya lang i-approve ng Pharmacy Admin ang sariling accreditation
  IF v_target_accred IS DISTINCT FROM p_accreditation_no THEN
    RETURN json_build_object('success', false, 'message', 'Not authorized for this account.');
  END IF;

  IF UPPER(p_decision) = 'APPROVED' THEN
    v_new_id_no := 'EOGS-' || LPAD(v_id::TEXT, 5, '0');
    UPDATE users SET status = 'APPROVED', id_no = v_new_id_no, role = 'USER'
    WHERE UPPER(username) = UPPER(p_username);
  ELSE
    UPDATE users SET status = UPPER(p_decision), decline_reason = p_decline_reason
    WHERE UPPER(username) = UPPER(p_username);
  END IF;

  RETURN json_build_object('success', true);
END;
$function$;

-- ----- approve_user(p_username text, p_decision text, p_decline_reason text, p_role text)
CREATE OR REPLACE FUNCTION public.approve_user(p_username text, p_decision text, p_decline_reason text DEFAULT NULL::text, p_role text DEFAULT NULL::text)
 RETURNS json
 LANGUAGE plpgsql
 SECURITY DEFINER
AS $function$
DECLARE
  v_id INT;
  v_new_id_no TEXT;
  v_account_type TEXT;
  v_accreditation TEXT;
  v_existing_pharmacy_admin INT;
  v_new_role TEXT;
BEGIN
  IF UPPER(p_decision) = 'APPROVED' THEN
    SELECT id, account_type, accreditation_no INTO v_id, v_account_type, v_accreditation
    FROM users WHERE UPPER(username) = UPPER(p_username);

    v_new_id_no := 'EOGS-' || LPAD(v_id::TEXT, 5, '0');

    IF v_account_type = 'PHARMACY' THEN
      IF p_role IN ('USER', 'PHARMACY_ADMIN') THEN
        v_new_role := p_role;
      ELSE
        SELECT COUNT(*) INTO v_existing_pharmacy_admin
        FROM users
        WHERE accreditation_no = v_accreditation
          AND role = 'PHARMACY_ADMIN'
          AND status = 'APPROVED';

        v_new_role := CASE WHEN v_existing_pharmacy_admin = 0 THEN 'PHARMACY_ADMIN' ELSE 'USER' END;
      END IF;

      UPDATE users
      SET status = 'APPROVED', id_no = v_new_id_no, role = v_new_role
      WHERE UPPER(username) = UPPER(p_username);
    ELSE
      -- BAGO: STAFF (o ibang non-PHARMACY type) — HUWAG babaguhin ang role, itakda lang ang status/id_no
      UPDATE users
      SET status = 'APPROVED', id_no = v_new_id_no
      WHERE UPPER(username) = UPPER(p_username);
    END IF;
  ELSE
    UPDATE users
    SET status = UPPER(p_decision), decline_reason = p_decline_reason
    WHERE UPPER(username) = UPPER(p_username);
  END IF;

  RETURN json_build_object('success', true);
END;
$function$;

-- ----- encode_deficiency(p_pro_region text, p_gacn_no text, p_gatn_no text, p_issue_category text, p_specific_issue text, p_facility text, p_facility_accreditation_no text, p_claimant_last_name text, p_claimant_first_name text, p_claimant_contact text, p_encoded_by text)
CREATE OR REPLACE FUNCTION public.encode_deficiency(p_pro_region text, p_gacn_no text, p_gatn_no text, p_issue_category text, p_specific_issue text, p_facility text, p_facility_accreditation_no text, p_claimant_last_name text, p_claimant_first_name text, p_claimant_contact text, p_encoded_by text)
 RETURNS json
 LANGUAGE plpgsql
 SECURITY DEFINER
AS $function$
DECLARE
  v_resolution TEXT;
  v_existing_count INT;
  v_clean_accred TEXT;
  v_expected_prefix TEXT;
BEGIN
  -- 1. I-check kung existing na ang GATN
  SELECT COUNT(*) INTO v_existing_count
  FROM deficiency_records
  WHERE gatn_no = p_gatn_no;

  IF v_existing_count > 0 THEN
    RETURN json_build_object('success', false, 'message', 'GATN already exists in the system.');
  END IF;

  -- 2. I-validate ang branch base sa PREFIX ng accreditation number
  v_clean_accred := UPPER(TRIM(p_facility_accreditation_no));

  v_expected_prefix := CASE UPPER(p_pro_region)
    WHEN 'PRONCR NORTH' THEN 'P91'
    WHEN 'PRONCR SOUTH' THEN 'P92'
    WHEN 'PRONCR CENTRAL' THEN 'P93'
    ELSE NULL
  END;

  IF v_expected_prefix IS NULL OR v_clean_accred NOT LIKE (v_expected_prefix || '%') THEN
    RETURN json_build_object(
      'success', false,
      'message', 'This Facility Accreditation No. (' || v_clean_accred || ') does not match your branch (' || p_pro_region || '). Please verify the accreditation number.'
    );
  END IF;

  -- 3. Kunin ang required resolution mula sa reference guide
  SELECT required_resolution INTO v_resolution
  FROM deficiency_resolution_guide
  WHERE issue_category = p_issue_category
    AND specific_issue = p_specific_issue
  LIMIT 1;

  IF v_resolution IS NULL THEN
    v_resolution := 'No matching resolution found. Please consult PMT-Claims.';
  END IF;

  -- 4. I-insert ang bagong record
  INSERT INTO deficiency_records (
    pro_region, gacn_no, gatn_no, issue_category, specific_issue,
    required_resolution, facility, claimant_last_name, claimant_first_name,
    claimant_email, claimant_contact, status, rtf_date, compliance_deadline,
    encoded_by, facility_accreditation_no
  ) VALUES (
    UPPER(p_pro_region), UPPER(p_gacn_no), UPPER(p_gatn_no), p_issue_category, p_specific_issue,
    v_resolution, UPPER(p_facility), UPPER(p_claimant_last_name), UPPER(p_claimant_first_name),
    LOWER(''), p_claimant_contact, 'RTF', NOW(), NOW() + INTERVAL '60 days',
    UPPER(p_encoded_by), v_clean_accred
  );

  RETURN json_build_object('success', true, 'resolution', v_resolution);
END;
$function$;

-- ----- encode_deficiency(p_pro_region text, p_gacn_no text, p_gatn_no text, p_issue_category text, p_specific_issue text, p_facility text, p_facility_accreditation_no text, p_claimant_last_name text, p_claimant_first_name text, p_claimant_contact text, p_encoded_by text, p_performed_by_username text)
CREATE OR REPLACE FUNCTION public.encode_deficiency(p_pro_region text, p_gacn_no text, p_gatn_no text, p_issue_category text, p_specific_issue text, p_facility text, p_facility_accreditation_no text, p_claimant_last_name text, p_claimant_first_name text, p_claimant_contact text, p_encoded_by text, p_performed_by_username text)
 RETURNS json
 LANGUAGE plpgsql
 SECURITY DEFINER
AS $function$
DECLARE
  v_resolution TEXT;
  v_existing_count INT;
  v_clean_accred TEXT;
  v_expected_prefix TEXT;
BEGIN
  SELECT COUNT(*) INTO v_existing_count FROM deficiency_records WHERE gatn_no = p_gatn_no;
  IF v_existing_count > 0 THEN
    RETURN json_build_object('success', false, 'message', 'GATN already exists in the system.');
  END IF;

  v_clean_accred := UPPER(TRIM(p_facility_accreditation_no));
  v_expected_prefix := CASE UPPER(p_pro_region)
    WHEN 'PRONCR NORTH' THEN 'P91'
    WHEN 'PRONCR SOUTH' THEN 'P92'
    WHEN 'PRONCR CENTRAL' THEN 'P93'
    ELSE NULL
  END;

  IF v_expected_prefix IS NULL OR v_clean_accred NOT LIKE (v_expected_prefix || '%') THEN
    RETURN json_build_object('success', false, 'message', 'This Facility Accreditation No. (' || v_clean_accred || ') does not match your branch (' || p_pro_region || '). Please verify the accreditation number.');
  END IF;

  SELECT required_resolution INTO v_resolution
  FROM deficiency_resolution_guide
  WHERE issue_category = p_issue_category AND specific_issue = p_specific_issue
  LIMIT 1;

  IF v_resolution IS NULL THEN
    v_resolution := 'No matching resolution found. Please consult PMT-Claims.';
  END IF;

  INSERT INTO deficiency_records (
    pro_region, gacn_no, gatn_no, issue_category, specific_issue,
    required_resolution, facility, claimant_last_name, claimant_first_name,
    claimant_email, claimant_contact, status, rtf_date, compliance_deadline,
    encoded_by, facility_accreditation_no
  ) VALUES (
    UPPER(p_pro_region), UPPER(p_gacn_no), UPPER(p_gatn_no), p_issue_category, p_specific_issue,
    v_resolution, UPPER(p_facility), UPPER(p_claimant_last_name), UPPER(p_claimant_first_name),
    LOWER(''), p_claimant_contact, 'RTF', NOW(), NOW() + INTERVAL '60 days',
    UPPER(p_encoded_by), v_clean_accred
  );

  PERFORM log_audit_trail(UPPER(p_gatn_no), 'ENCODE', p_performed_by_username, UPPER(p_pro_region), 'New deficiency record created.');

  RETURN json_build_object('success', true, 'resolution', v_resolution);
END;
$function$;

-- ----- encode_deficiency(p_pro_region text, p_gacn_no text, p_gatn_no text, p_issue_category text, p_specific_issue text, p_facility text, p_facility_accreditation_no text, p_claimant_last_name text, p_claimant_first_name text, p_claimant_contact text, p_encoded_by text, p_performed_by_username text, p_claim_amount numeric)
CREATE OR REPLACE FUNCTION public.encode_deficiency(p_pro_region text, p_gacn_no text, p_gatn_no text, p_issue_category text, p_specific_issue text, p_facility text, p_facility_accreditation_no text, p_claimant_last_name text, p_claimant_first_name text, p_claimant_contact text, p_encoded_by text, p_performed_by_username text, p_claim_amount numeric DEFAULT NULL::numeric)
 RETURNS json
 LANGUAGE plpgsql
 SECURITY DEFINER
AS $function$
DECLARE
  v_resolution TEXT;
  v_existing_count INT;
  v_clean_accred TEXT;
  v_expected_prefix TEXT;
BEGIN
  SELECT COUNT(*) INTO v_existing_count FROM deficiency_records WHERE gatn_no = p_gatn_no;
  IF v_existing_count > 0 THEN
    RETURN json_build_object('success', false, 'message', 'GATN already exists in the system.');
  END IF;

  v_clean_accred := UPPER(TRIM(p_facility_accreditation_no));
  v_expected_prefix := CASE UPPER(p_pro_region)
    WHEN 'PRONCR NORTH' THEN 'P91'
    WHEN 'PRONCR SOUTH' THEN 'P92'
    WHEN 'PRONCR CENTRAL' THEN 'P93'
    ELSE NULL
  END;

  IF v_expected_prefix IS NULL OR v_clean_accred NOT LIKE (v_expected_prefix || '%') THEN
    RETURN json_build_object('success', false, 'message', 'This Facility Accreditation No. (' || v_clean_accred || ') does not match your branch (' || p_pro_region || '). Please verify the accreditation number.');
  END IF;

  -- BAGO: kinikilala natin kung TALAGANG walang match, kumpara sa may match pero blangko ang resolution
  SELECT required_resolution INTO v_resolution
  FROM deficiency_resolution_guide
  WHERE issue_category = p_issue_category AND specific_issue = p_specific_issue
  LIMIT 1;

  IF NOT FOUND THEN
    v_resolution := 'No matching resolution found. Please consult PMT-Claims.';
  END IF;
  -- Kung FOUND pero NULL ang resolution, mananatiling NULL ito (sadyang blangko)

  INSERT INTO deficiency_records (
    pro_region, gacn_no, gatn_no, issue_category, specific_issue,
    required_resolution, facility, claimant_last_name, claimant_first_name,
    claimant_email, claimant_contact, status, rtf_date, compliance_deadline,
    encoded_by, facility_accreditation_no, claim_amount
  ) VALUES (
    UPPER(p_pro_region), UPPER(p_gacn_no), UPPER(p_gatn_no), p_issue_category, p_specific_issue,
    v_resolution, UPPER(p_facility), UPPER(p_claimant_last_name), UPPER(p_claimant_first_name),
    LOWER(''), p_claimant_contact, 'RTF', NOW(), NOW() + INTERVAL '60 days',
    UPPER(p_encoded_by), v_clean_accred, p_claim_amount
  );

  PERFORM log_audit_trail(UPPER(p_gatn_no), 'ENCODE', p_performed_by_username, UPPER(p_pro_region), 'New deficiency record created.');

  RETURN json_build_object('success', true, 'resolution', COALESCE(v_resolution, 'No specific action indicated.'));
END;
$function$;

-- ----- pharmacy_admin_reset_password(p_username text, p_accreditation_no text, p_new_password text)
CREATE OR REPLACE FUNCTION public.pharmacy_admin_reset_password(p_username text, p_accreditation_no text, p_new_password text)
 RETURNS json
 LANGUAGE plpgsql
 SECURITY DEFINER
AS $function$
DECLARE
  v_target_accred TEXT;
BEGIN
  SELECT accreditation_no INTO v_target_accred FROM users WHERE UPPER(username) = UPPER(p_username);

  IF v_target_accred IS DISTINCT FROM p_accreditation_no THEN
    RETURN json_build_object('success', false, 'message', 'Not authorized for this account.');
  END IF;

  UPDATE users SET password = crypt(p_new_password, gen_salt('bf')) WHERE UPPER(username) = UPPER(p_username);

  RETURN json_build_object('success', true);
END;
$function$;

-- ----- register_user(p_username text, p_password text, p_account_type text, p_facility text, p_branch text)
CREATE OR REPLACE FUNCTION public.register_user(p_username text, p_password text, p_account_type text, p_facility text, p_branch text)
 RETURNS json
 LANGUAGE plpgsql
 SECURITY DEFINER
AS $function$
DECLARE
  v_existing INT;
BEGIN
  SELECT COUNT(*) INTO v_existing FROM users WHERE UPPER(username) = UPPER(p_username);

  IF v_existing > 0 THEN
    RETURN json_build_object('success', false, 'message', 'Username already taken.');
  END IF;

  INSERT INTO users (username, password, role, facility, branch, account_type, status)
  VALUES (UPPER(p_username), p_password, 'USER', UPPER(p_facility), UPPER(p_branch), p_account_type, 'PENDING');

  RETURN json_build_object('success', true);
END;
$function$;

-- ----- resolve_deficiency(p_gatn_no text, p_resolved_by text)
CREATE OR REPLACE FUNCTION public.resolve_deficiency(p_gatn_no text, p_resolved_by text)
 RETURNS void
 LANGUAGE plpgsql
 SECURITY DEFINER
AS $function$
begin
  update deficiency_records
  set status = 'RESOLVED',
      resolved_by = p_resolved_by,
      resolved_timestamp = now()
  where gatn_no = p_gatn_no
    and status = 'REFILED';

  if not found then
    raise exception 'No REFILED record found for GATN %', p_gatn_no;
  end if;
end;
$function$;

-- ----- set_branch_admin(p_username text, p_make_admin boolean)
CREATE OR REPLACE FUNCTION public.set_branch_admin(p_username text, p_make_admin boolean)
 RETURNS json
 LANGUAGE plpgsql
 SECURITY DEFINER
AS $function$
BEGIN
  IF p_make_admin THEN
    UPDATE users SET role = 'BRANCH_ADMIN' WHERE UPPER(username) = UPPER(p_username);
  ELSE
    UPDATE users SET role = 'STAFF' WHERE UPPER(username) = UPPER(p_username);
  END IF;

  RETURN json_build_object('success', true);
END;
$function$;

-- ----- set_staff_active_status(p_username text, p_accreditation_no text, p_active boolean)
CREATE OR REPLACE FUNCTION public.set_staff_active_status(p_username text, p_accreditation_no text, p_active boolean)
 RETURNS json
 LANGUAGE plpgsql
 SECURITY DEFINER
AS $function$
DECLARE
  v_target_accred TEXT;
BEGIN
  SELECT accreditation_no INTO v_target_accred FROM users WHERE UPPER(username) = UPPER(p_username);

  IF v_target_accred IS DISTINCT FROM p_accreditation_no THEN
    RETURN json_build_object('success', false, 'message', 'Not authorized for this account.');
  END IF;

  UPDATE users
  SET status = CASE WHEN p_active THEN 'APPROVED' ELSE 'DEACTIVATED' END
  WHERE UPPER(username) = UPPER(p_username);

  RETURN json_build_object('success', true);
END;
$function$;

-- ----- set_staff_active_status_by_admin(p_username text, p_requesting_branch text, p_active boolean)
CREATE OR REPLACE FUNCTION public.set_staff_active_status_by_admin(p_username text, p_requesting_branch text, p_active boolean)
 RETURNS json
 LANGUAGE plpgsql
 SECURITY DEFINER
AS $function$
DECLARE
  v_target_branch TEXT;
BEGIN
  SELECT branch INTO v_target_branch FROM users WHERE UPPER(username) = UPPER(p_username);

  IF p_requesting_branch IS NOT NULL AND p_requesting_branch != ''
     AND UPPER(v_target_branch) IS DISTINCT FROM UPPER(p_requesting_branch) THEN
    RETURN json_build_object('success', false, 'message', 'Not authorized for this account.');
  END IF;

  UPDATE users
  SET status = CASE WHEN p_active THEN 'APPROVED' ELSE 'DEACTIVATED' END
  WHERE UPPER(username) = UPPER(p_username);

  RETURN json_build_object('success', true);
END;
$function$;

-- ----- toggle_gatn_paid_status(p_gatn_no text, p_paid boolean)
CREATE OR REPLACE FUNCTION public.toggle_gatn_paid_status(p_gatn_no text, p_paid boolean)
 RETURNS json
 LANGUAGE plpgsql
 SECURITY DEFINER
AS $function$
BEGIN
  UPDATE deficiency_records SET paid = p_paid WHERE gatn_no = UPPER(p_gatn_no);
  RETURN json_build_object('success', true);
END;
$function$;

-- ----- update_staff_email(p_username text, p_accreditation_no text, p_new_email text)
CREATE OR REPLACE FUNCTION public.update_staff_email(p_username text, p_accreditation_no text, p_new_email text)
 RETURNS json
 LANGUAGE plpgsql
 SECURITY DEFINER
AS $function$
DECLARE
  v_target_accred TEXT;
BEGIN
  SELECT accreditation_no INTO v_target_accred FROM users WHERE UPPER(username) = UPPER(p_username);

  -- Security check: kaya lang i-edit ng Pharmacy Admin ang staff sa SARILING accreditation
  IF v_target_accred IS DISTINCT FROM p_accreditation_no THEN
    RETURN json_build_object('success', false, 'message', 'Not authorized for this account.');
  END IF;

  UPDATE users SET email = p_new_email WHERE UPPER(username) = UPPER(p_username);

  RETURN json_build_object('success', true);
END;
$function$;

-- ----- update_staff_email_by_admin(p_username text, p_requesting_branch text, p_new_email text)
CREATE OR REPLACE FUNCTION public.update_staff_email_by_admin(p_username text, p_requesting_branch text, p_new_email text)
 RETURNS json
 LANGUAGE plpgsql
 SECURITY DEFINER
AS $function$
DECLARE
  v_target_branch TEXT;
BEGIN
  SELECT branch INTO v_target_branch FROM users WHERE UPPER(username) = UPPER(p_username);

  -- Kung may branch restriction (BRANCH_ADMIN), i-verify na parehong branch
  -- Kung NULL ang p_requesting_branch (global ADMIN), walang restriction
  IF p_requesting_branch IS NOT NULL AND p_requesting_branch != '' 
     AND UPPER(v_target_branch) IS DISTINCT FROM UPPER(p_requesting_branch) THEN
    RETURN json_build_object('success', false, 'message', 'Not authorized for this account.');
  END IF;

  UPDATE users SET email = p_new_email WHERE UPPER(username) = UPPER(p_username);

  RETURN json_build_object('success', true);
END;
$function$;

-- ----- update_staff_employee_id_by_admin(p_username text, p_requesting_branch text, p_new_employee_id text)
CREATE OR REPLACE FUNCTION public.update_staff_employee_id_by_admin(p_username text, p_requesting_branch text, p_new_employee_id text)
 RETURNS json
 LANGUAGE plpgsql
 SECURITY DEFINER
AS $function$
DECLARE
  v_target_branch TEXT;
  v_existing INT;
BEGIN
  SELECT branch INTO v_target_branch FROM users WHERE UPPER(username) = UPPER(p_username);

  IF p_requesting_branch IS NOT NULL AND p_requesting_branch != ''
     AND UPPER(v_target_branch) IS DISTINCT FROM UPPER(p_requesting_branch) THEN
    RETURN json_build_object('success', false, 'message', 'Not authorized for this account.');
  END IF;

  -- BAGO: siguraduhing walang ibang account na gumagamit na ng bagong Employee ID (na siya ring magiging username)
  SELECT COUNT(*) INTO v_existing
  FROM users
  WHERE UPPER(username) = UPPER(p_new_employee_id)
    AND UPPER(username) != UPPER(p_username);

  IF v_existing > 0 THEN
    RETURN json_build_object('success', false, 'message', 'This Employee ID is already used by another account.');
  END IF;

  -- BAGO: sabay na-uupdate ang employee_id_no AT ang username, para hindi masira ang login
  UPDATE users
  SET employee_id_no = p_new_employee_id,
      username = UPPER(p_new_employee_id)
  WHERE UPPER(username) = UPPER(p_username);

  RETURN json_build_object('success', true);
END;
$function$;

-- ----- update_staff_pin(p_username text, p_accreditation_no text, p_new_pin text)
CREATE OR REPLACE FUNCTION public.update_staff_pin(p_username text, p_accreditation_no text, p_new_pin text)
 RETURNS json
 LANGUAGE plpgsql
 SECURITY DEFINER
AS $function$
DECLARE
  v_target_accred TEXT;
  v_existing INT;
BEGIN
  SELECT accreditation_no INTO v_target_accred FROM users WHERE UPPER(username) = UPPER(p_username);

  IF v_target_accred IS DISTINCT FROM p_accreditation_no THEN
    RETURN json_build_object('success', false, 'message', 'Not authorized for this account.');
  END IF;

  -- BAGO: siguraduhing walang ibang account na gumagamit na ng bagong PIN (na siya ring magiging username)
  SELECT COUNT(*) INTO v_existing
  FROM users
  WHERE UPPER(username) = UPPER(p_new_pin)
    AND UPPER(username) != UPPER(p_username);

  IF v_existing > 0 THEN
    RETURN json_build_object('success', false, 'message', 'This PIN is already used by another account.');
  END IF;

  -- BAGO: sabay na-uupdate ang philhealth_pin AT ang username, para hindi masira ang login
  UPDATE users
  SET philhealth_pin = p_new_pin,
      username = UPPER(p_new_pin)
  WHERE UPPER(username) = UPPER(p_username);

  RETURN json_build_object('success', true);
END;
$function$;

-- ----- update_tracker_fields(p_gatn_no text, p_requesting_branch text, p_remarks text, p_action_taken text, p_date_processed date)
CREATE OR REPLACE FUNCTION public.update_tracker_fields(p_gatn_no text, p_requesting_branch text, p_remarks text, p_action_taken text, p_date_processed date DEFAULT NULL::date)
 RETURNS json
 LANGUAGE plpgsql
 SECURITY DEFINER
AS $function$
DECLARE
  v_target_branch TEXT;
BEGIN
  SELECT pro_region INTO v_target_branch FROM deficiency_records WHERE gatn_no = UPPER(p_gatn_no);

  IF v_target_branch IS NULL THEN
    RETURN json_build_object('success', false, 'message', 'Record not found.');
  END IF;

  IF p_requesting_branch IS NOT NULL AND p_requesting_branch != ''
     AND UPPER(v_target_branch) IS DISTINCT FROM UPPER(p_requesting_branch) THEN
    RETURN json_build_object('success', false, 'message', 'Not authorized for this record.');
  END IF;

  UPDATE deficiency_records
  SET tracker_remarks = p_remarks,
      tracker_action_taken = p_action_taken,
      tracker_date_processed = p_date_processed
  WHERE gatn_no = UPPER(p_gatn_no);

  RETURN json_build_object('success', true);
END;
$function$;

-- ----- generate_password_reset_otp(p_username text)
CREATE OR REPLACE FUNCTION public.generate_password_reset_otp(p_username text)
 RETURNS json
 LANGUAGE plpgsql
 SECURITY DEFINER
AS $function$
DECLARE
  v_exists INT;
  v_otp TEXT;
BEGIN
  SELECT COUNT(*) INTO v_exists FROM users WHERE UPPER(username) = UPPER(p_username);

  IF v_exists = 0 THEN
    RETURN json_build_object('success', false, 'message', 'Username not found.');
  END IF;

  v_otp := LPAD(FLOOR(RANDOM() * 1000000)::TEXT, 6, '0');

  INSERT INTO password_reset_requests (username, otp, expires_at)
  VALUES (UPPER(p_username), v_otp, NOW() + INTERVAL '15 minutes');

  RETURN json_build_object('success', true);
END;
$function$;

-- ----- get_refiled_deficiencies()
CREATE OR REPLACE FUNCTION public.get_refiled_deficiencies()
 RETURNS SETOF deficiency_records
 LANGUAGE sql
 SECURITY DEFINER
AS $function$
  select *
  from deficiency_records
  where status = 'REFILED'
  order by refile_timestamp asc nulls last;
$function$;

-- ----- get_approved_staff_accounts(p_branch text)
CREATE OR REPLACE FUNCTION public.get_approved_staff_accounts(p_branch text DEFAULT NULL::text)
 RETURNS json
 LANGUAGE plpgsql
 SECURITY DEFINER
AS $function$
DECLARE
  result JSON;
BEGIN
  SELECT json_agg(row_to_json(u) ORDER BY u.branch, u.username) INTO result
  FROM (
    SELECT username, facility, branch, role, account_type, email, status, employee_id_no
    FROM users
    WHERE account_type = 'STAFF'
      AND status IN ('APPROVED', 'DEACTIVATED')
      AND (p_branch IS NULL OR p_branch = '' OR UPPER(branch) = UPPER(p_branch))
  ) u;

  RETURN COALESCE(result, '[]'::json);
END;
$function$;

-- ----- get_branch_deficiencies(p_branch text)
CREATE OR REPLACE FUNCTION public.get_branch_deficiencies(p_branch text)
 RETURNS json
 LANGUAGE plpgsql
 SECURITY DEFINER
AS $function$
DECLARE
  v_code text;
  result json;
BEGIN
  v_code := CASE
    WHEN p_branch ILIKE '%NORTH%' THEN '91'
    WHEN p_branch ILIKE '%SOUTH%' THEN '92'
    WHEN p_branch ILIKE '%CENTRAL%' THEN '93'
    ELSE NULL
  END;

  IF v_code IS NULL THEN
    RETURN '[]'::json;
  END IF;

  SELECT json_agg(row_to_json(d) ORDER BY d.created_at DESC) INTO result
  FROM (
    SELECT r.gatn_no, r.gacn_no, r.facility, r.facility_accreditation_no,
           r.issue_category, r.specific_issue, r.status, r.created_at,
           r.resolved_timestamp,
           u.username AS resolved_by_username
    FROM deficiency_records r
    LEFT JOIN users u ON u.id_no = r.resolved_by
    WHERE r.facility_accreditation_no LIKE 'P' || v_code || '%'
       OR r.facility_accreditation_no LIKE 'H' || v_code || '%'
  ) d;

  RETURN COALESCE(result, '[]'::json);
END;
$function$;

GRANT EXECUTE ON FUNCTION public.log_audit_trail(text, text, text, text, text) TO PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION public.log_account_audit(text, text, text, text, text) TO PUBLIC, anon, authenticated;

COMMIT;
