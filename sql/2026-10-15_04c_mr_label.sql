-- =====================================================================
-- EGOS Hakbang 4c: "REFILED (MR)" label
-- Petsa: 2026-10-15
-- Idinadagdag ang is_mr_filing sa get_admin_history, get_gamot_tracker at
-- get_facility_history para maipakita ng page ang "REFILED (MR)".
-- Walang binagong logic. LIGTAS PATAKBUHIN KAHIT KAILAN.
-- ROLLBACK: patakbuhin ulit ang 04 (admin_history, tracker) at 02b2 (facility_history)
-- =====================================================================

BEGIN;
CREATE OR REPLACE FUNCTION public.get_admin_history(p_date_from text, p_date_to text, p_status text, p_accreditation_no text, p_branch text)
 RETURNS json
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path = public, extensions
AS $function$
DECLARE
  result JSON;
  clean_status TEXT := UPPER(COALESCE(p_status, 'ALL'));
  v_caller public.users;
BEGIN
  -- kapag may session token, ang server ang nagtatakda ng branch
  v_caller := _current_caller(ARRAY['ADMIN', 'BRANCH_ADMIN', 'STAFF', 'BAS']);
  IF v_caller.id IS NOT NULL THEN
    p_branch := CASE WHEN v_caller.role = 'ADMIN' THEN NULL ELSE COALESCE(v_caller.branch, '__NONE__') END;
  END IF;

  SELECT json_agg(row_to_json(d) ORDER BY d.created_at DESC) INTO result
  FROM (
    SELECT gatn_no, gacn_no, pro_region, facility_accreditation_no, facility,
           issue_category, specific_issue, required_resolution, status,
           claimant_last_name, claimant_first_name, claimant_contact,
           rtf_date, compliance_deadline, refile_timestamp, created_at,
           mr_deadline, denied_at, is_mr_filing
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

CREATE OR REPLACE FUNCTION public.get_gamot_tracker(p_branch text DEFAULT NULL::text)
 RETURNS json
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path = public, extensions
AS $function$
DECLARE
  result JSON;
  v_caller public.users;
BEGIN
  -- kapag may session token, ang server ang nagtatakda ng branch
  v_caller := _current_caller(ARRAY['ADMIN', 'BRANCH_ADMIN', 'STAFF', 'BAS']);
  IF v_caller.id IS NOT NULL THEN
    p_branch := CASE WHEN v_caller.role = 'ADMIN' THEN NULL ELSE COALESCE(v_caller.branch, '__NONE__') END;
  END IF;

  SELECT json_agg(row_to_json(d) ORDER BY d.created_at DESC) INTO result
  FROM (
    SELECT
      facility_accreditation_no, facility, gacn_no, new_gacn_no, gatn_no, claim_amount,
      issue_category, specific_issue, created_at, status, review_remarks,
      required_resolution, rtf_date, paid, tracker_remarks, tracker_action_taken,
      tracker_date_processed, resolved_timestamp, compliance_deadline,
      mr_deadline, denied_at, is_mr_filing
    FROM deficiency_records
    WHERE (p_branch IS NULL OR p_branch = '' OR UPPER(pro_region) = UPPER(p_branch))
  ) d;

  RETURN COALESCE(result, '[]'::json);
END;
$function$;

CREATE OR REPLACE FUNCTION public.get_facility_history(p_accreditation_no text, p_date_from text, p_date_to text, p_status text)
 RETURNS json
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path = public, extensions
AS $function$
DECLARE
  result JSON;
  clean_status TEXT := UPPER(COALESCE(p_status, 'ALL'));
  v_caller public.users;
BEGIN
  -- BAGO (2b): kapag may session token, sariling accreditation lang
  v_caller := _current_caller(ARRAY['USER', 'PHARMACY_ADMIN']);
  IF v_caller.id IS NOT NULL THEN
    p_accreditation_no := COALESCE(v_caller.accreditation_no, '__NONE__');
  END IF;

  SELECT json_agg(row_to_json(d) ORDER BY d.created_at DESC) INTO result
  FROM (
    SELECT gatn_no, gacn_no, new_gacn_no, issue_category, specific_issue, required_resolution,
           status, rtf_date, compliance_deadline, refile_timestamp, created_at,
           mr_deadline, is_mr_filing
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

COMMIT;
