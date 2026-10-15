-- =====================================================================
-- ROLLBACK para sa 2026-10-15_02b2_remaining_functions.sql
-- Patakbuhin LAMANG kung may nasira pagkatapos ng Hakbang 2b Grupo 2-5.
-- Ibinabalik ang 25 function sa dating bersyon (kinuha sa live database
-- noong 2026-10-15). HINDI ginagalaw ang _current_caller (Grupo 1).
-- =====================================================================

BEGIN;

-- ----- encode_deficiency(p_pro_region text, p_gacn_no text, p_gatn_no text, p_issue_category text, p_specific_issue text, p_facility text, p_facility_accreditation_no text, p_claimant_last_name text, p_claimant_first_name text, p_claimant_contact text, p_encoded_by text, p_performed_by_username text, p_claim_amount numeric, p_send_to_pharmacy boolean)
CREATE OR REPLACE FUNCTION public.encode_deficiency(p_pro_region text, p_gacn_no text, p_gatn_no text, p_issue_category text, p_specific_issue text, p_facility text, p_facility_accreditation_no text, p_claimant_last_name text, p_claimant_first_name text, p_claimant_contact text, p_encoded_by text, p_performed_by_username text, p_claim_amount numeric DEFAULT NULL::numeric, p_send_to_pharmacy boolean DEFAULT true)
 RETURNS json
 LANGUAGE plpgsql
 SECURITY DEFINER
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
BEGIN
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

-- ----- edit_deficiency_record(p_gatn_no text, p_requesting_branch text, p_gacn_no text, p_issue_category text, p_specific_issue text, p_facility text, p_facility_accreditation_no text, p_claimant_last_name text, p_claimant_first_name text, p_claimant_contact text, p_performed_by_username text)
CREATE OR REPLACE FUNCTION public.edit_deficiency_record(p_gatn_no text, p_requesting_branch text, p_gacn_no text, p_issue_category text, p_specific_issue text, p_facility text, p_facility_accreditation_no text, p_claimant_last_name text, p_claimant_first_name text, p_claimant_contact text, p_performed_by_username text)
 RETURNS json
 LANGUAGE plpgsql
 SECURITY DEFINER
AS $function$
DECLARE
  v_target_branch TEXT;
  v_resolution TEXT;
BEGIN
  SELECT pro_region INTO v_target_branch FROM deficiency_records WHERE gatn_no = UPPER(p_gatn_no);

  IF v_target_branch IS NULL THEN
    RETURN json_build_object('success', false, 'message', 'Record not found.');
  END IF;

  IF p_requesting_branch IS NOT NULL AND p_requesting_branch != ''
     AND UPPER(v_target_branch) IS DISTINCT FROM UPPER(p_requesting_branch) THEN
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

  PERFORM log_audit_trail(UPPER(p_gatn_no), 'EDIT', p_performed_by_username, v_target_branch, 'Record fields updated.');

  RETURN json_build_object('success', true);
END;
$function$;

-- ----- delete_deficiency_record(p_gatn_no text, p_requesting_branch text, p_performed_by_username text)
CREATE OR REPLACE FUNCTION public.delete_deficiency_record(p_gatn_no text, p_requesting_branch text, p_performed_by_username text)
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

  PERFORM log_audit_trail(UPPER(p_gatn_no), 'DELETE', p_performed_by_username, v_target_branch, 'Record permanently deleted.');

  DELETE FROM deficiency_records WHERE gatn_no = UPPER(p_gatn_no);

  RETURN json_build_object('success', true);
END;
$function$;

-- ----- resolve_deficiency(p_gatn_no text, p_resolved_by text, p_new_status text, p_review_remarks text)
CREATE OR REPLACE FUNCTION public.resolve_deficiency(p_gatn_no text, p_resolved_by text, p_new_status text, p_review_remarks text DEFAULT NULL::text)
 RETURNS json
 LANGUAGE plpgsql
 SECURITY DEFINER
AS $function$
DECLARE
  v_branch TEXT;
BEGIN
  SELECT pro_region INTO v_branch FROM deficiency_records WHERE gatn_no = UPPER(p_gatn_no);

  IF UPPER(p_new_status) = 'RTF' THEN
    UPDATE deficiency_records
    SET status = 'RTF', review_remarks = p_review_remarks
    WHERE gatn_no = UPPER(p_gatn_no);

    PERFORM log_audit_trail(UPPER(p_gatn_no), 'RETURN_FOR_CORRECTION', p_resolved_by, v_branch, p_review_remarks);
  ELSE
    UPDATE deficiency_records
    SET status = UPPER(p_new_status), resolved_by = UPPER(p_resolved_by), resolved_timestamp = NOW()
    WHERE gatn_no = UPPER(p_gatn_no);

    PERFORM log_audit_trail(UPPER(p_gatn_no), 'RESOLVE', p_resolved_by, v_branch, 'Marked as ' || UPPER(p_new_status) || '.');
  END IF;

  RETURN json_build_object('success', true);
END;
$function$;

-- ----- toggle_gatn_paid_status(p_gatn_no text, p_paid boolean, p_performed_by_username text)
CREATE OR REPLACE FUNCTION public.toggle_gatn_paid_status(p_gatn_no text, p_paid boolean, p_performed_by_username text DEFAULT NULL::text)
 RETURNS json
 LANGUAGE plpgsql
 SECURITY DEFINER
AS $function$
DECLARE
  v_branch TEXT;
BEGIN
  SELECT pro_region INTO v_branch FROM deficiency_records WHERE gatn_no = UPPER(p_gatn_no);

  UPDATE deficiency_records SET paid = p_paid WHERE gatn_no = UPPER(p_gatn_no);

  IF p_performed_by_username IS NOT NULL THEN
    PERFORM log_audit_trail(
      UPPER(p_gatn_no),
      'PAID_STATUS_CHANGE',
      p_performed_by_username,
      v_branch,
      CASE WHEN p_paid THEN 'Marked as PAID.' ELSE 'Marked as UNPAID.' END
    );
  END IF;

  RETURN json_build_object('success', true);
END;
$function$;

-- ----- update_tracker_fields(p_gatn_no text, p_requesting_branch text, p_remarks text, p_action_taken text, p_date_processed date, p_performed_by_username text)
CREATE OR REPLACE FUNCTION public.update_tracker_fields(p_gatn_no text, p_requesting_branch text, p_remarks text, p_action_taken text, p_date_processed date DEFAULT NULL::date, p_performed_by_username text DEFAULT NULL::text)
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

  IF p_performed_by_username IS NOT NULL THEN
    PERFORM log_audit_trail(UPPER(p_gatn_no), 'TRACKER_UPDATE', p_performed_by_username, v_target_branch, 'GAMOT Tracker fields updated (remarks/action taken/date processed).');
  END IF;

  RETURN json_build_object('success', true);
END;
$function$;

-- ----- assign_new_gacn_batch(p_gatn_list text[], p_new_gacn_no text, p_performed_by text)
CREATE OR REPLACE FUNCTION public.assign_new_gacn_batch(p_gatn_list text[], p_new_gacn_no text, p_performed_by text)
 RETURNS json
 LANGUAGE plpgsql
 SECURITY DEFINER
AS $function$
DECLARE
  v_gatn TEXT;
  v_branch TEXT;
  v_updated_count INT := 0;
  v_not_found JSONB := '[]'::JSONB;
BEGIN
  FOREACH v_gatn IN ARRAY p_gatn_list
  LOOP
    SELECT pro_region INTO v_branch FROM deficiency_records WHERE gatn_no = UPPER(v_gatn);

    IF v_branch IS NULL THEN
      v_not_found := v_not_found || to_jsonb(UPPER(v_gatn));
    ELSE
      UPDATE deficiency_records
      SET new_gacn_no = UPPER(p_new_gacn_no)
      WHERE gatn_no = UPPER(v_gatn);

      PERFORM log_audit_trail(UPPER(v_gatn), 'NEW_GACN_ASSIGNED', p_performed_by, v_branch, 'New GACN assigned: ' || UPPER(p_new_gacn_no));

      v_updated_count := v_updated_count + 1;
    END IF;
  END LOOP;

  RETURN json_build_object(
    'success', true,
    'updated_count', v_updated_count,
    'not_found', v_not_found
  );
END;
$function$;

-- ----- get_pending_pharmacy_staff(p_accreditation_no text)
CREATE OR REPLACE FUNCTION public.get_pending_pharmacy_staff(p_accreditation_no text)
 RETURNS json
 LANGUAGE plpgsql
 SECURITY DEFINER
AS $function$
DECLARE
  result JSON;
BEGIN
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

-- ----- approve_pharmacy_staff(p_username text, p_decision text, p_decline_reason text, p_accreditation_no text, p_performed_by text)
CREATE OR REPLACE FUNCTION public.approve_pharmacy_staff(p_username text, p_decision text, p_decline_reason text, p_accreditation_no text, p_performed_by text DEFAULT NULL::text)
 RETURNS json
 LANGUAGE plpgsql
 SECURITY DEFINER
AS $function$
DECLARE
  v_id INT;
  v_new_id_no TEXT;
  v_target_accred TEXT;
  v_branch TEXT;
BEGIN
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

-- ----- get_my_pharmacy_staff(p_accreditation_no text)
CREATE OR REPLACE FUNCTION public.get_my_pharmacy_staff(p_accreditation_no text)
 RETURNS json
 LANGUAGE plpgsql
 SECURITY DEFINER
AS $function$
DECLARE
  result JSON;
BEGIN
  SELECT json_agg(row_to_json(u)) INTO result
  FROM (
    SELECT username, facility, branch, role, status, email, philhealth_pin
    FROM users
    WHERE account_type = 'PHARMACY'
      AND accreditation_no = p_accreditation_no
      AND status IN ('APPROVED', 'DEACTIVATED')
      AND role != 'PHARMACY_ADMIN'
    ORDER BY username
  ) u;

  RETURN COALESCE(result, '[]'::json);
END;
$function$;

-- ----- set_staff_active_status(p_username text, p_accreditation_no text, p_active boolean, p_performed_by text)
CREATE OR REPLACE FUNCTION public.set_staff_active_status(p_username text, p_accreditation_no text, p_active boolean, p_performed_by text DEFAULT NULL::text)
 RETURNS json
 LANGUAGE plpgsql
 SECURITY DEFINER
AS $function$
DECLARE
  v_target_accred TEXT;
  v_branch TEXT;
BEGIN
  SELECT accreditation_no, branch INTO v_target_accred, v_branch FROM users WHERE UPPER(username) = UPPER(p_username);

  IF v_target_accred IS DISTINCT FROM p_accreditation_no THEN
    RETURN json_build_object('success', false, 'message', 'Not authorized for this account.');
  END IF;

  UPDATE users
  SET status = CASE WHEN p_active THEN 'APPROVED' ELSE 'DEACTIVATED' END
  WHERE UPPER(username) = UPPER(p_username);

  IF p_performed_by IS NOT NULL THEN
    PERFORM log_account_audit(p_username, CASE WHEN p_active THEN 'REACTIVATED' ELSE 'DEACTIVATED' END, p_performed_by, v_branch, 'Changed by Pharmacy Admin.');
  END IF;

  RETURN json_build_object('success', true);
END;
$function$;

-- ----- update_staff_email(p_username text, p_accreditation_no text, p_new_email text, p_performed_by text)
CREATE OR REPLACE FUNCTION public.update_staff_email(p_username text, p_accreditation_no text, p_new_email text, p_performed_by text DEFAULT NULL::text)
 RETURNS json
 LANGUAGE plpgsql
 SECURITY DEFINER
AS $function$
DECLARE
  v_target_accred TEXT;
  v_branch TEXT;
BEGIN
  SELECT accreditation_no, branch INTO v_target_accred, v_branch FROM users WHERE UPPER(username) = UPPER(p_username);

  IF v_target_accred IS DISTINCT FROM p_accreditation_no THEN
    RETURN json_build_object('success', false, 'message', 'Not authorized for this account.');
  END IF;

  UPDATE users SET email = p_new_email WHERE UPPER(username) = UPPER(p_username);

  IF p_performed_by IS NOT NULL THEN
    PERFORM log_account_audit(p_username, 'EMAIL_UPDATED', p_performed_by, v_branch, 'Email updated by Pharmacy Admin.');
  END IF;

  RETURN json_build_object('success', true);
END;
$function$;

-- ----- update_staff_pin(p_username text, p_accreditation_no text, p_new_pin text, p_performed_by text)
CREATE OR REPLACE FUNCTION public.update_staff_pin(p_username text, p_accreditation_no text, p_new_pin text, p_performed_by text DEFAULT NULL::text)
 RETURNS json
 LANGUAGE plpgsql
 SECURITY DEFINER
AS $function$
DECLARE
  v_target_accred TEXT;
  v_branch TEXT;
  v_existing INT;
BEGIN
  SELECT accreditation_no, branch INTO v_target_accred, v_branch FROM users WHERE UPPER(username) = UPPER(p_username);

  IF v_target_accred IS DISTINCT FROM p_accreditation_no THEN
    RETURN json_build_object('success', false, 'message', 'Not authorized for this account.');
  END IF;

  SELECT COUNT(*) INTO v_existing
  FROM users
  WHERE UPPER(username) = UPPER(p_new_pin)
    AND UPPER(username) != UPPER(p_username);

  IF v_existing > 0 THEN
    RETURN json_build_object('success', false, 'message', 'This PIN is already used by another account.');
  END IF;

  UPDATE users
  SET philhealth_pin = p_new_pin,
      username = UPPER(p_new_pin)
  WHERE UPPER(username) = UPPER(p_username);

  IF p_performed_by IS NOT NULL THEN
    PERFORM log_account_audit(UPPER(p_new_pin), 'PIN_UPDATED', p_performed_by, v_branch, 'PIN (and login username) changed from ' || p_username || ' to ' || UPPER(p_new_pin) || '.');
  END IF;

  RETURN json_build_object('success', true);
END;
$function$;

-- ----- pharmacy_admin_reset_password(p_username text, p_accreditation_no text, p_new_password text, p_performed_by text)
CREATE OR REPLACE FUNCTION public.pharmacy_admin_reset_password(p_username text, p_accreditation_no text, p_new_password text, p_performed_by text DEFAULT NULL::text)
 RETURNS json
 LANGUAGE plpgsql
 SECURITY DEFINER
AS $function$
DECLARE
  v_target_accred TEXT;
  v_branch TEXT;
BEGIN
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

-- ----- find_deficiency_by_gatn(p_gatn_no text, p_accreditation_no text)
CREATE OR REPLACE FUNCTION public.find_deficiency_by_gatn(p_gatn_no text, p_accreditation_no text)
 RETURNS json
 LANGUAGE plpgsql
 SECURITY DEFINER
AS $function$
DECLARE
  v_record RECORD;
BEGIN
  SELECT * INTO v_record
  FROM deficiency_records
  WHERE UPPER(gatn_no) = UPPER(p_gatn_no);

  IF v_record IS NULL THEN
    RETURN json_build_object('found', false, 'message', 'GATN not found.');
  END IF;

  IF UPPER(v_record.facility_accreditation_no) IS DISTINCT FROM UPPER(p_accreditation_no) THEN
    RETURN json_build_object('found', false, 'message', 'This GATN does not belong to your facility.');
  END IF;

  -- BAGO: hindi makikita/ma-refile ang mga PROCESSING record (internal-only, hindi pa na-send sa pharmacy)
  IF v_record.status = 'PROCESSING' THEN
    RETURN json_build_object('found', false, 'message', 'GATN not found.');
  END IF;

  RETURN json_build_object(
    'found', true,
    'claimant_name', v_record.claimant_first_name || ' ' || v_record.claimant_last_name,
    'facility', v_record.facility,
    'gacn_no', v_record.gacn_no,
    'issue_category', v_record.issue_category,
    'specific_issue', v_record.specific_issue,
    'required_resolution', v_record.required_resolution,
    'compliance_deadline', v_record.compliance_deadline,
    'status', v_record.status
  );
END;
$function$;

-- ----- submit_refile(p_gatn_no text, p_refile_file_link text, p_refile_notes text, p_accreditation_no text)
CREATE OR REPLACE FUNCTION public.submit_refile(p_gatn_no text, p_refile_file_link text, p_refile_notes text, p_accreditation_no text)
 RETURNS json
 LANGUAGE plpgsql
 SECURITY DEFINER
AS $function$
DECLARE
  v_record RECORD;
  v_is_late BOOLEAN;
BEGIN
  SELECT * INTO v_record
  FROM deficiency_records
  WHERE gatn_no = UPPER(p_gatn_no);

  IF v_record IS NULL THEN
    RETURN json_build_object('success', false, 'message', 'Record not found.');
  END IF;

  IF UPPER(v_record.facility_accreditation_no) IS DISTINCT FROM UPPER(p_accreditation_no) THEN
    RETURN json_build_object('success', false, 'message', 'This GATN does not belong to your facility. You are not authorized to refile it.');
  END IF;

  v_is_late := (NOW() > v_record.compliance_deadline);

  UPDATE deficiency_records
  SET status = 'REFILED',
      refile_timestamp = NOW(),
      refile_file_link = p_refile_file_link,
      refile_notes = p_refile_notes,
      is_late_submission = v_is_late
  WHERE gatn_no = UPPER(p_gatn_no);

  RETURN json_build_object('success', true, 'is_late', v_is_late);
END;
$function$;

-- ----- get_facility_deficiencies(p_accreditation_no text)
CREATE OR REPLACE FUNCTION public.get_facility_deficiencies(p_accreditation_no text)
 RETURNS json
 LANGUAGE plpgsql
 SECURITY DEFINER
AS $function$
DECLARE
  result JSON;
BEGIN
  SELECT json_agg(row_to_json(d) ORDER BY d.compliance_deadline ASC NULLS LAST) INTO result
  FROM (
    SELECT gatn_no, gacn_no, new_gacn_no, issue_category, specific_issue, required_resolution,
           status, rtf_date, compliance_deadline, refile_timestamp, created_at, review_remarks,
           CASE
             WHEN compliance_deadline < NOW() THEN 'OVERDUE'
             WHEN compliance_deadline < NOW() + INTERVAL '5 days' THEN 'DUE_SOON'
             ELSE 'ON_TRACK'
           END AS urgency
    FROM deficiency_records
    WHERE UPPER(facility_accreditation_no) = UPPER(p_accreditation_no)
      AND status = 'RTF'
  ) d;

  RETURN COALESCE(result, '[]'::json);
END;
$function$;

-- ----- get_facility_history(p_accreditation_no text, p_date_from text, p_date_to text, p_status text)
CREATE OR REPLACE FUNCTION public.get_facility_history(p_accreditation_no text, p_date_from text, p_date_to text, p_status text)
 RETURNS json
 LANGUAGE plpgsql
 SECURITY DEFINER
AS $function$
DECLARE
  result JSON;
  clean_status TEXT := UPPER(COALESCE(p_status, 'ALL'));
BEGIN
  SELECT json_agg(row_to_json(d) ORDER BY d.created_at DESC) INTO result
  FROM (
    SELECT gatn_no, gacn_no, new_gacn_no, issue_category, specific_issue, required_resolution,
           status, rtf_date, compliance_deadline, refile_timestamp, created_at
    FROM deficiency_records
    WHERE UPPER(facility_accreditation_no) = UPPER(p_accreditation_no)
      AND status != 'PROCESSING'
      AND (p_date_from IS NULL OR p_date_from = '' OR created_at::date >= p_date_from::date)
      AND (p_date_to IS NULL OR p_date_to = '' OR created_at::date <= p_date_to::date)
      AND (clean_status = 'ALL' OR status = clean_status)
  ) d;

  RETURN COALESCE(result, '[]'::json);
END;
$function$;

-- ----- get_admin_history(p_date_from text, p_date_to text, p_status text, p_accreditation_no text, p_branch text)
CREATE OR REPLACE FUNCTION public.get_admin_history(p_date_from text, p_date_to text, p_status text, p_accreditation_no text, p_branch text)
 RETURNS json
 LANGUAGE plpgsql
 SECURITY DEFINER
AS $function$
DECLARE
  result JSON;
  clean_status TEXT := UPPER(COALESCE(p_status, 'ALL'));
BEGIN
  SELECT json_agg(row_to_json(d) ORDER BY d.created_at DESC) INTO result
  FROM (
    SELECT gatn_no, gacn_no, pro_region, facility_accreditation_no, facility,
           issue_category, specific_issue, required_resolution, status,
           claimant_last_name, claimant_first_name, claimant_contact,
           rtf_date, compliance_deadline, refile_timestamp, created_at
    FROM deficiency_records
    WHERE (p_date_from IS NULL OR p_date_from = '' OR created_at::date >= p_date_from::date)
      AND (p_date_to IS NULL OR p_date_to = '' OR created_at::date <= p_date_to::date)
      AND (clean_status = 'ALL' OR status = clean_status)
      AND (p_accreditation_no IS NULL OR p_accreditation_no = '' OR UPPER(facility_accreditation_no) = UPPER(p_accreditation_no))
      AND (p_branch IS NULL OR p_branch = '' OR UPPER(pro_region) = UPPER(p_branch))
  ) d;

  RETURN COALESCE(result, '[]'::json);
END;
$function$;

-- ----- get_analytics_data(p_branch text)
CREATE OR REPLACE FUNCTION public.get_analytics_data(p_branch text DEFAULT NULL::text)
 RETURNS json
 LANGUAGE plpgsql
 SECURITY DEFINER
AS $function$
DECLARE
  v_summary JSON;
  v_by_category JSON;
  v_by_status JSON;
  v_by_month JSON;
  v_by_branch JSON;
BEGIN
  -- Summary counts
  SELECT json_build_object(
    'total_records', COUNT(*),
    'total_rtf', COUNT(*) FILTER (WHERE status = 'RTF'),
    'total_refiled', COUNT(*) FILTER (WHERE status = 'REFILED'),
    'total_resolved', COUNT(*) FILTER (WHERE status = 'RESOLVED'),
    'total_processing', COUNT(*) FILTER (WHERE status = 'PROCESSING'),
    'total_late', COUNT(*) FILTER (WHERE is_late_submission = true),
    'total_claim_amount', COALESCE(SUM(claim_amount), 0),
    'total_paid_amount', COALESCE(SUM(claim_amount) FILTER (WHERE paid = true), 0),
    'total_unpaid_amount', COALESCE(SUM(claim_amount) FILTER (WHERE paid = false OR paid IS NULL), 0)
  ) INTO v_summary
  FROM deficiency_records
  WHERE (p_branch IS NULL OR p_branch = '' OR UPPER(pro_region) = UPPER(p_branch));

  -- Per issue category
  SELECT json_agg(row_to_json(c)) INTO v_by_category
  FROM (
    SELECT issue_category, COUNT(*) AS total
    FROM deficiency_records
    WHERE (p_branch IS NULL OR p_branch = '' OR UPPER(pro_region) = UPPER(p_branch))
    GROUP BY issue_category
    ORDER BY total DESC
  ) c;

  -- Per status
  SELECT json_agg(row_to_json(s)) INTO v_by_status
  FROM (
    SELECT status, COUNT(*) AS total
    FROM deficiency_records
    WHERE (p_branch IS NULL OR p_branch = '' OR UPPER(pro_region) = UPPER(p_branch))
    GROUP BY status
  ) s;

  -- Per month (huling 6 buwan)
  SELECT json_agg(row_to_json(m)) INTO v_by_month
  FROM (
    SELECT to_char(date_trunc('month', created_at), 'YYYY-MM') AS month_label, COUNT(*) AS total
    FROM deficiency_records
    WHERE (p_branch IS NULL OR p_branch = '' OR UPPER(pro_region) = UPPER(p_branch))
      AND created_at >= NOW() - INTERVAL '6 months'
    GROUP BY date_trunc('month', created_at)
    ORDER BY date_trunc('month', created_at)
  ) m;

  -- Per branch (para sa comparison, kasama kahit may p_branch filter na tinawag ito para sa ibang bagay)
  SELECT json_agg(row_to_json(b)) INTO v_by_branch
  FROM (
    SELECT pro_region, COUNT(*) AS total
    FROM deficiency_records
    GROUP BY pro_region
    ORDER BY pro_region
  ) b;

  RETURN json_build_object(
    'summary', v_summary,
    'by_category', COALESCE(v_by_category, '[]'::json),
    'by_status', COALESCE(v_by_status, '[]'::json),
    'by_month', COALESCE(v_by_month, '[]'::json),
    'by_branch', COALESCE(v_by_branch, '[]'::json)
  );
END;
$function$;

-- ----- get_gacn_compliance(p_branch text)
CREATE OR REPLACE FUNCTION public.get_gacn_compliance(p_branch text DEFAULT NULL::text)
 RETURNS json
 LANGUAGE plpgsql
 SECURITY DEFINER
AS $function$
DECLARE
  result JSON;
BEGIN
  SELECT json_agg(row_to_json(d) ORDER BY d.compliance_pct DESC, d.gacn_no ASC) INTO result
  FROM (
    SELECT
      gacn_no,
      pro_region,
      facility_accreditation_no,
      COUNT(*) AS total_gatn,
      COUNT(*) FILTER (WHERE status = 'RESOLVED') AS resolved_gatn,
      ROUND(100.0 * COUNT(*) FILTER (WHERE status = 'RESOLVED') / COUNT(*), 1) AS compliance_pct
    FROM deficiency_records
    WHERE (p_branch IS NULL OR p_branch = '' OR UPPER(pro_region) = UPPER(p_branch))
    GROUP BY gacn_no, pro_region, facility_accreditation_no
  ) d;

  RETURN COALESCE(result, '[]'::json);
END;
$function$;

-- ----- get_gamot_tracker(p_branch text)
CREATE OR REPLACE FUNCTION public.get_gamot_tracker(p_branch text DEFAULT NULL::text)
 RETURNS json
 LANGUAGE plpgsql
 SECURITY DEFINER
AS $function$
DECLARE
  result JSON;
BEGIN
  SELECT json_agg(row_to_json(d) ORDER BY d.created_at DESC) INTO result
  FROM (
    SELECT
      facility_accreditation_no, facility, gacn_no, new_gacn_no, gatn_no, claim_amount,
      issue_category, specific_issue, created_at, status, review_remarks,
      required_resolution, rtf_date, paid, tracker_remarks, tracker_action_taken,
      tracker_date_processed, resolved_timestamp, compliance_deadline
    FROM deficiency_records
    WHERE (p_branch IS NULL OR p_branch = '' OR UPPER(pro_region) = UPPER(p_branch))
  ) d;

  RETURN COALESCE(result, '[]'::json);
END;
$function$;

-- ----- get_audit_trail(p_gatn_no text, p_branch text)
CREATE OR REPLACE FUNCTION public.get_audit_trail(p_gatn_no text DEFAULT NULL::text, p_branch text DEFAULT NULL::text)
 RETURNS json
 LANGUAGE plpgsql
 SECURITY DEFINER
AS $function$
DECLARE
  result JSON;
BEGIN
  SELECT json_agg(row_to_json(t) ORDER BY t.performed_at DESC) INTO result
  FROM (
    SELECT gatn_no, action, performed_by_username, performed_by_employee_id, performed_at, details
    FROM audit_trail
    WHERE (p_gatn_no IS NULL OR p_gatn_no = '' OR UPPER(gatn_no) = UPPER(p_gatn_no))
      AND (p_branch IS NULL OR p_branch = '' OR UPPER(branch) = UPPER(p_branch))
    LIMIT 500
  ) t;

  RETURN COALESCE(result, '[]'::json);
END;
$function$;

-- ----- get_deleted_records(p_branch text)
CREATE OR REPLACE FUNCTION public.get_deleted_records(p_branch text DEFAULT NULL::text)
 RETURNS json
 LANGUAGE plpgsql
 SECURITY DEFINER
AS $function$
DECLARE
  result JSON;
BEGIN
  SELECT json_agg(row_to_json(t) ORDER BY t.performed_at DESC) INTO result
  FROM (
    SELECT gatn_no, performed_by_username, performed_by_employee_id, performed_at, details, branch
    FROM audit_trail
    WHERE action = 'DELETE'
      AND (p_branch IS NULL OR p_branch = '' OR UPPER(branch) = UPPER(p_branch))
    LIMIT 500
  ) t;

  RETURN COALESCE(result, '[]'::json);
END;
$function$;

-- ----- get_refiled_submissions(p_branch text)
CREATE OR REPLACE FUNCTION public.get_refiled_submissions(p_branch text DEFAULT NULL::text)
 RETURNS json
 LANGUAGE plpgsql
 SECURITY DEFINER
AS $function$
DECLARE
  result JSON;
BEGIN
  SELECT json_agg(row_to_json(d) ORDER BY d.refile_timestamp ASC) INTO result
  FROM (
    SELECT gatn_no, gacn_no, facility_accreditation_no, issue_category, specific_issue,
           refile_timestamp, refile_file_link, refile_notes, is_late_submission
    FROM deficiency_records
    WHERE status = 'REFILED'
      AND (p_branch IS NULL OR p_branch = '' OR UPPER(pro_region) = UPPER(p_branch))
  ) d;

  RETURN COALESCE(result, '[]'::json);
END;
$function$;

COMMIT;
