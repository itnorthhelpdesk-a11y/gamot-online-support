-- =====================================================================
-- ROLLBACK para sa 2026-10-15_04_mr_appeal.sql (at 04b)
-- Ibinabalik ang 8 function sa bersyon bago ang Hakbang 4 (galing sa
-- 2026-10-15_02b2_remaining_functions.sql), binubura ang freeze trigger,
-- process_mr_deadlines, reopen_denied_record, at ang schedule.
-- Iniiwan ang bagong columns at mr_notice_queue (hindi nakakaapekto).
-- PAALALA: kung may record nang FOR_MR o DENIED, mananatili ang status
-- nila; ibalik nang manual kung kailangan.
-- =====================================================================

BEGIN;

DO $$ BEGIN
  IF EXISTS (SELECT 1 FROM pg_extension WHERE extname = 'pg_cron') THEN
    PERFORM cron.unschedule(jobid) FROM cron.job WHERE jobname = 'egos-mr-deadlines';
  END IF;
END $$;

DROP TRIGGER IF EXISTS deficiency_records_denied_freeze ON public.deficiency_records;
DROP FUNCTION IF EXISTS public._block_denied_changes();
DROP FUNCTION IF EXISTS public.process_mr_deadlines();
DROP FUNCTION IF EXISTS public.reopen_denied_record(text, text);
DROP FUNCTION IF EXISTS public.submit_refile(text, text, text, text, text);
-- ----- submit_refile (2b)
CREATE OR REPLACE FUNCTION public.submit_refile(p_gatn_no text, p_refile_file_link text, p_refile_notes text, p_accreditation_no text)
 RETURNS json
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path = public, extensions
AS $function$
DECLARE
  v_record RECORD;
  v_is_late BOOLEAN;
  v_caller public.users;
BEGIN
  -- BAGO (2b): kapag may session token, sariling accreditation lang
  v_caller := _current_caller(ARRAY['USER', 'PHARMACY_ADMIN']);
  IF v_caller.id IS NOT NULL THEN
    p_accreditation_no := COALESCE(v_caller.accreditation_no, '__NONE__');
  END IF;

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

  -- BAGO (2b): itala sa audit trail ang refile (dati walang record)
  PERFORM log_audit_trail(UPPER(p_gatn_no), 'REFILE', v_caller.username, v_record.pro_region,
    CASE WHEN v_is_late THEN 'Refiled by facility (LATE submission).' ELSE 'Refiled by facility.' END);

  RETURN json_build_object('success', true, 'is_late', v_is_late);
END;
$function$;

-- ----- resolve_deficiency (2b)
CREATE OR REPLACE FUNCTION public.resolve_deficiency(p_gatn_no text, p_resolved_by text, p_new_status text, p_review_remarks text DEFAULT NULL::text)
 RETURNS json
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path = public, extensions
AS $function$
DECLARE
  v_branch TEXT;
  v_caller public.users;
BEGIN
  SELECT pro_region INTO v_branch FROM deficiency_records WHERE gatn_no = UPPER(p_gatn_no);

  -- BAGO (2b): kapag may session token, server ang nagtatakda ng reviewer + branch check
  v_caller := _current_caller(ARRAY['ADMIN', 'BRANCH_ADMIN', 'STAFF', 'BAS']);
  IF v_caller.id IS NOT NULL THEN
    p_resolved_by := v_caller.username;
    IF UPPER(COALESCE(v_caller.facility, '')) = 'ACCOUNTING' THEN
      RETURN json_build_object('success', false, 'message', 'Not authorized to review refiled submissions.');
    END IF;
    IF v_caller.role <> 'ADMIN' AND UPPER(v_branch) IS DISTINCT FROM UPPER(COALESCE(v_caller.branch, '__NONE__')) THEN
      RETURN json_build_object('success', false, 'message', 'Not authorized for this record.');
    END IF;
  END IF;

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

-- ----- find_deficiency_by_gatn (2b)
CREATE OR REPLACE FUNCTION public.find_deficiency_by_gatn(p_gatn_no text, p_accreditation_no text)
 RETURNS json
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path = public, extensions
AS $function$
DECLARE
  v_record RECORD;
  v_caller public.users;
BEGIN
  -- BAGO (2b): kapag may session token, sariling accreditation lang
  v_caller := _current_caller(ARRAY['USER', 'PHARMACY_ADMIN']);
  IF v_caller.id IS NOT NULL THEN
    p_accreditation_no := COALESCE(v_caller.accreditation_no, '__NONE__');
  END IF;

  SELECT * INTO v_record
  FROM deficiency_records
  WHERE UPPER(gatn_no) = UPPER(p_gatn_no);

  IF v_record IS NULL THEN
    RETURN json_build_object('found', false, 'message', 'GATN not found.');
  END IF;

  IF UPPER(v_record.facility_accreditation_no) IS DISTINCT FROM UPPER(p_accreditation_no) THEN
    RETURN json_build_object('found', false, 'message', 'This GATN does not belong to your facility.');
  END IF;

  -- hindi makikita/ma-refile ang mga PROCESSING record (internal-only, hindi pa na-send sa pharmacy)
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

-- ----- get_facility_deficiencies (2b)
CREATE OR REPLACE FUNCTION public.get_facility_deficiencies(p_accreditation_no text)
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
  v_caller := _current_caller(ARRAY['USER', 'PHARMACY_ADMIN']);
  IF v_caller.id IS NOT NULL THEN
    p_accreditation_no := COALESCE(v_caller.accreditation_no, '__NONE__');
  END IF;

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

-- ----- get_refiled_submissions (2b)
CREATE OR REPLACE FUNCTION public.get_refiled_submissions(p_branch text DEFAULT NULL::text)
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
  v_caller := _current_caller(ARRAY['ADMIN', 'BRANCH_ADMIN', 'STAFF', 'BAS']);
  IF v_caller.id IS NOT NULL THEN
    p_branch := CASE WHEN v_caller.role = 'ADMIN' THEN NULL ELSE COALESCE(v_caller.branch, '__NONE__') END;
  END IF;

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

-- ----- get_gamot_tracker (2b)
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
  -- BAGO (2b): kapag may session token, ang server ang nagtatakda ng branch
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
      tracker_date_processed, resolved_timestamp, compliance_deadline
    FROM deficiency_records
    WHERE (p_branch IS NULL OR p_branch = '' OR UPPER(pro_region) = UPPER(p_branch))
  ) d;

  RETURN COALESCE(result, '[]'::json);
END;
$function$;

-- ----- get_admin_history (2b)
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
  -- BAGO (2b): kapag may session token, ang server ang nagtatakda ng branch
  v_caller := _current_caller(ARRAY['ADMIN', 'BRANCH_ADMIN', 'STAFF', 'BAS']);
  IF v_caller.id IS NOT NULL THEN
    p_branch := CASE WHEN v_caller.role = 'ADMIN' THEN NULL ELSE COALESCE(v_caller.branch, '__NONE__') END;
  END IF;

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

-- ----- get_analytics_data (2b)
CREATE OR REPLACE FUNCTION public.get_analytics_data(p_branch text DEFAULT NULL::text)
 RETURNS json
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path = public, extensions
AS $function$
DECLARE
  v_summary JSON;
  v_by_category JSON;
  v_by_status JSON;
  v_by_month JSON;
  v_by_branch JSON;
  v_caller public.users;
BEGIN
  -- BAGO (2b): kapag may session token, ang server ang nagtatakda ng branch
  v_caller := _current_caller(ARRAY['ADMIN', 'BRANCH_ADMIN', 'STAFF', 'BAS']);
  IF v_caller.id IS NOT NULL THEN
    p_branch := CASE WHEN v_caller.role = 'ADMIN' THEN NULL ELSE COALESCE(v_caller.branch, '__NONE__') END;
  END IF;

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

COMMIT;
