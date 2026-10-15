-- =====================================================================
-- EGOS Hakbang 4: Motion for Reconsideration (MR) / Appeal
-- Petsa: 2026-10-15
--
-- PROCESS:
--   RTF (60 araw mula sa RTF date; hindi nagre-restart kapag ibinalik)
--     -> hindi na-refile sa loob ng 60 araw -> FOR_MR (+60 araw mula sa notice)
--        + email notice sa lahat ng pharmacy accounts ng facility
--     -> hindi nag-file ng MR sa loob ng 60 araw -> DENIED (frozen)
--   Habang REFILED, hindi tumatakbo ang orasan.
--   Ibinalik for correction: RTF -> RTF, FOR_MR -> FOR_MR (parehong deadline).
--   ADMIN lang ang makakapag-reopen ng DENIED (may dahilan, nasa audit).
--
-- ANG FILE NA ITO (ligtas patakbuhin kahit kailan; WALA pang awtomatikong
-- paglipat ng status hangga't hindi pinapatakbo ang 04b):
--   1. Bagong columns + table na mr_notice_queue (patunay ng email notice)
--   2. Trigger: hindi mababago / mabubura ang DENIED (maliban sa reopen)
--   3. process_mr_deadlines(): ang awtomatikong paglipat (tatawagin ng 04b)
--   4. reopen_denied_record(): ADMIN lang
--   5. Binago: submit_refile (+ MR letter), resolve_deficiency,
--      find_deficiency_by_gatn, get_facility_deficiencies,
--      get_refiled_submissions, get_gamot_tracker, get_admin_history,
--      get_analytics_data
--
-- ROLLBACK: 2026-10-15_04_rollback.sql
-- =====================================================================

BEGIN;

-- =====================================================================
-- 1. COLUMNS + NOTICE QUEUE
-- =====================================================================
ALTER TABLE public.deficiency_records
  ADD COLUMN IF NOT EXISTS mr_notice_at  TIMESTAMPTZ,
  ADD COLUMN IF NOT EXISTS mr_deadline   TIMESTAMPTZ,
  ADD COLUMN IF NOT EXISTS denied_at     TIMESTAMPTZ,
  ADD COLUMN IF NOT EXISTS is_mr_filing  BOOLEAN NOT NULL DEFAULT FALSE,
  ADD COLUMN IF NOT EXISTS mr_letter_link TEXT;

CREATE TABLE IF NOT EXISTS public.mr_notice_queue (
  id          BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  gatn_no     TEXT NOT NULL,
  kind        TEXT NOT NULL DEFAULT 'MR_NOTICE',   -- MR_NOTICE, REOPENED
  status      TEXT NOT NULL DEFAULT 'PENDING',     -- PENDING, SENT, PARTIAL, FAILED, NO_RECIPIENT
  recipients  TEXT,
  error       TEXT,
  attempts    INT NOT NULL DEFAULT 0,
  created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  sent_at     TIMESTAMPTZ
);
ALTER TABLE public.mr_notice_queue ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON public.mr_notice_queue FROM PUBLIC, anon, authenticated;


-- =====================================================================
-- 2. FREEZE: hindi mababago o mabubura ang DENIED
-- =====================================================================
CREATE OR REPLACE FUNCTION public._block_denied_changes()
 RETURNS trigger
 LANGUAGE plpgsql
AS $function$
BEGIN
  IF OLD.status = 'DENIED'
     AND COALESCE(current_setting('egos.allow_denied_change', true), '') <> 'on' THEN
    RAISE EXCEPTION 'This claim (GATN %) is DENIED and frozen. Only the Admin can reopen it.', OLD.gatn_no;
  END IF;

  IF TG_OP = 'DELETE' THEN
    RETURN OLD;
  END IF;
  RETURN NEW;
END;
$function$;

DROP TRIGGER IF EXISTS deficiency_records_denied_freeze ON public.deficiency_records;
CREATE TRIGGER deficiency_records_denied_freeze
  BEFORE UPDATE OR DELETE ON public.deficiency_records
  FOR EACH ROW EXECUTE FUNCTION public._block_denied_changes();


-- =====================================================================
-- 3. AWTOMATIKONG PAGLIPAT NG STATUS (tatawagin ng pg_cron sa 04b)
-- =====================================================================
CREATE OR REPLACE FUNCTION public.process_mr_deadlines()
 RETURNS json
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path = public, extensions
AS $function$
DECLARE
  r RECORD;
  v_moved INT := 0;
  v_denied INT := 0;
  v_mr_deadline TIMESTAMPTZ;
BEGIN
  -- RTF na lumampas sa 60 araw -> FOR_MR (+60 araw mula ngayon) + email notice
  FOR r IN
    SELECT gatn_no, pro_region, compliance_deadline
    FROM deficiency_records
    WHERE status = 'RTF' AND compliance_deadline < NOW()
    FOR UPDATE
  LOOP
    v_mr_deadline := NOW() + INTERVAL '60 days';

    UPDATE deficiency_records
    SET status = 'FOR_MR', mr_notice_at = NOW(), mr_deadline = v_mr_deadline
    WHERE gatn_no = r.gatn_no;

    PERFORM log_audit_trail(r.gatn_no, 'MOVED_TO_MR', 'SYSTEM', r.pro_region,
      'Not complied within the 60-day compliance period (deadline ' ||
      to_char(r.compliance_deadline AT TIME ZONE 'Asia/Manila', 'YYYY-MM-DD') ||
      '). Moved to Motion for Reconsideration / Appeal until ' ||
      to_char(v_mr_deadline AT TIME ZONE 'Asia/Manila', 'YYYY-MM-DD') || '.');

    INSERT INTO mr_notice_queue (gatn_no, kind) VALUES (r.gatn_no, 'MR_NOTICE');
    v_moved := v_moved + 1;
  END LOOP;

  -- FOR_MR na lumampas sa MR deadline -> DENIED (frozen)
  FOR r IN
    SELECT gatn_no, pro_region, mr_deadline
    FROM deficiency_records
    WHERE status = 'FOR_MR' AND mr_deadline < NOW()
    FOR UPDATE
  LOOP
    UPDATE deficiency_records
    SET status = 'DENIED', denied_at = NOW()
    WHERE gatn_no = r.gatn_no;

    PERFORM log_audit_trail(r.gatn_no, 'AUTO_DENIED', 'SYSTEM', r.pro_region,
      'No Motion for Reconsideration / Appeal filed on or before ' ||
      to_char(r.mr_deadline AT TIME ZONE 'Asia/Manila', 'YYYY-MM-DD') ||
      '. Claim denied with finality; record frozen.');

    v_denied := v_denied + 1;
  END LOOP;

  RETURN json_build_object('moved_to_mr', v_moved, 'denied', v_denied, 'ran_at', NOW());
END;
$function$;
REVOKE EXECUTE ON FUNCTION public.process_mr_deadlines() FROM PUBLIC, anon, authenticated;


-- =====================================================================
-- 4. REOPEN NG DENIED (ADMIN lang)
-- =====================================================================
CREATE OR REPLACE FUNCTION public.reopen_denied_record(p_gatn_no text, p_reason text)
 RETURNS json
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path = public, extensions
AS $function$
DECLARE
  v_caller public.users;
  v_rec RECORD;
  v_mr_deadline TIMESTAMPTZ := NOW() + INTERVAL '60 days';
BEGIN
  v_caller := _current_caller(ARRAY['ADMIN']);

  IF COALESCE(TRIM(p_reason), '') = '' THEN
    RETURN json_build_object('success', false, 'message', 'A reason is required to reopen a denied claim.');
  END IF;

  SELECT gatn_no, status, pro_region INTO v_rec FROM deficiency_records WHERE gatn_no = UPPER(p_gatn_no);

  IF NOT FOUND THEN
    RETURN json_build_object('success', false, 'message', 'Record not found.');
  END IF;

  IF v_rec.status <> 'DENIED' THEN
    RETURN json_build_object('success', false, 'message', 'Only DENIED claims can be reopened.');
  END IF;

  -- Pansamantalang payagan ang pagbabago ng DENIED (sa transaction na ito lang)
  PERFORM set_config('egos.allow_denied_change', 'on', true);

  UPDATE deficiency_records
  SET status = 'FOR_MR', denied_at = NULL, mr_notice_at = NOW(), mr_deadline = v_mr_deadline
  WHERE gatn_no = v_rec.gatn_no;

  INSERT INTO mr_notice_queue (gatn_no, kind) VALUES (v_rec.gatn_no, 'REOPENED');

  PERFORM log_audit_trail(v_rec.gatn_no, 'REOPENED', v_caller.username, v_rec.pro_region,
    'Denied claim reopened for Motion for Reconsideration / Appeal until ' ||
    to_char(v_mr_deadline AT TIME ZONE 'Asia/Manila', 'YYYY-MM-DD') || '. Reason: ' || TRIM(p_reason));

  RETURN json_build_object('success', true, 'mr_deadline', v_mr_deadline);
END;
$function$;


-- =====================================================================
-- 5. SUBMIT REFILE (+ MR letter)
--    Bagong parameter p_mr_letter_link (optional) kaya kailangang i-DROP muna.
-- =====================================================================
DROP FUNCTION IF EXISTS public.submit_refile(text, text, text, text);

CREATE FUNCTION public.submit_refile(p_gatn_no text, p_refile_file_link text, p_refile_notes text, p_accreditation_no text, p_mr_letter_link text DEFAULT NULL::text)
 RETURNS json
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path = public, extensions
AS $function$
DECLARE
  v_record RECORD;
  v_is_late BOOLEAN;
  v_is_mr BOOLEAN;
  v_caller public.users;
BEGIN
  -- kapag may session token, sariling accreditation lang
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

  -- BAGO (4): RTF at FOR_MR lang ang puwedeng i-refile
  IF v_record.status = 'DENIED' THEN
    RETURN json_build_object('success', false, 'message', 'This claim has been DENIED with finality and can no longer be refiled.');
  ELSIF v_record.status = 'REFILED' THEN
    RETURN json_build_object('success', false, 'message', 'This GATN has already been refiled and is awaiting PhilHealth review.');
  ELSIF v_record.status NOT IN ('RTF', 'FOR_MR') THEN
    RETURN json_build_object('success', false, 'message', 'This GATN cannot be refiled (status: ' || v_record.status || ').');
  END IF;

  v_is_mr := (v_record.status = 'FOR_MR');

  IF v_is_mr AND COALESCE(TRIM(p_mr_letter_link), '') = '' THEN
    RETURN json_build_object('success', false, 'message', 'A Motion for Reconsideration / Appeal letter is required for this GATN.');
  END IF;

  -- LATE: lumampas sa 60 araw pero hindi pa nailipat sa FOR_MR ng scheduled job
  v_is_late := (NOT v_is_mr AND NOW() > v_record.compliance_deadline);

  UPDATE deficiency_records
  SET status = 'REFILED',
      refile_timestamp = NOW(),
      refile_file_link = p_refile_file_link,
      refile_notes = p_refile_notes,
      is_late_submission = v_is_late,
      is_mr_filing = v_is_mr,
      mr_letter_link = CASE WHEN v_is_mr THEN p_mr_letter_link ELSE mr_letter_link END
  WHERE gatn_no = UPPER(p_gatn_no);

  PERFORM log_audit_trail(UPPER(p_gatn_no), CASE WHEN v_is_mr THEN 'MR_FILED' ELSE 'REFILE' END,
    v_caller.username, v_record.pro_region,
    CASE WHEN v_is_mr THEN 'Motion for Reconsideration / Appeal filed by facility (with MR letter).'
         WHEN v_is_late THEN 'Refiled by facility (LATE submission).'
         ELSE 'Refiled by facility.' END);

  RETURN json_build_object('success', true, 'is_late', v_is_late, 'is_mr', v_is_mr);
END;
$function$;


-- =====================================================================
-- 6. RESOLVE / RETURN FOR CORRECTION
--    Ibinalik ang MR filing -> FOR_MR (parehong MR deadline); ang iba -> RTF.
-- =====================================================================
CREATE OR REPLACE FUNCTION public.resolve_deficiency(p_gatn_no text, p_resolved_by text, p_new_status text, p_review_remarks text DEFAULT NULL::text)
 RETURNS json
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path = public, extensions
AS $function$
DECLARE
  v_branch TEXT;
  v_mr_notice_at TIMESTAMPTZ;
  v_return_status TEXT;
  v_caller public.users;
BEGIN
  SELECT pro_region, mr_notice_at INTO v_branch, v_mr_notice_at FROM deficiency_records WHERE gatn_no = UPPER(p_gatn_no);

  -- kapag may session token, server ang nagtatakda ng reviewer + branch check
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
    -- BAGO (4): nasa MR na dati -> bumalik sa FOR_MR; kung hindi -> RTF (parehong deadline)
    v_return_status := CASE WHEN v_mr_notice_at IS NOT NULL THEN 'FOR_MR' ELSE 'RTF' END;

    UPDATE deficiency_records
    SET status = v_return_status, review_remarks = p_review_remarks
    WHERE gatn_no = UPPER(p_gatn_no);

    PERFORM log_audit_trail(UPPER(p_gatn_no), 'RETURN_FOR_CORRECTION', p_resolved_by, v_branch,
      COALESCE(p_review_remarks, '') || CASE WHEN v_return_status = 'FOR_MR' THEN ' (returned to MR / Appeal; same MR deadline)' ELSE '' END);
  ELSE
    UPDATE deficiency_records
    SET status = UPPER(p_new_status), resolved_by = UPPER(p_resolved_by), resolved_timestamp = NOW()
    WHERE gatn_no = UPPER(p_gatn_no);

    PERFORM log_audit_trail(UPPER(p_gatn_no), 'RESOLVE', p_resolved_by, v_branch, 'Marked as ' || UPPER(p_new_status) || '.');
  END IF;

  RETURN json_build_object('success', true);
END;
$function$;


-- =====================================================================
-- 7. PHARMACY: hanapin ang GATN (kasama na ang MR info)
-- =====================================================================
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
  -- kapag may session token, sariling accreditation lang
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
    'status', v_record.status,
    'mr_deadline', v_record.mr_deadline,
    'denied_at', v_record.denied_at
  );
END;
$function$;


-- =====================================================================
-- 8. PHARMACY: My Deficiencies (RTF + FOR_MR)
-- =====================================================================
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
  -- kapag may session token, sariling accreditation lang
  v_caller := _current_caller(ARRAY['USER', 'PHARMACY_ADMIN']);
  IF v_caller.id IS NOT NULL THEN
    p_accreditation_no := COALESCE(v_caller.accreditation_no, '__NONE__');
  END IF;

  SELECT json_agg(row_to_json(d) ORDER BY d.effective_deadline ASC NULLS LAST) INTO result
  FROM (
    SELECT gatn_no, gacn_no, new_gacn_no, issue_category, specific_issue, required_resolution,
           status, rtf_date, compliance_deadline, mr_deadline, refile_timestamp, created_at, review_remarks,
           -- BAGO (4): FOR_MR = MR deadline ang binibilang
           CASE WHEN status = 'FOR_MR' THEN mr_deadline ELSE compliance_deadline END AS effective_deadline,
           CASE
             WHEN (CASE WHEN status = 'FOR_MR' THEN mr_deadline ELSE compliance_deadline END) < NOW() THEN 'OVERDUE'
             WHEN (CASE WHEN status = 'FOR_MR' THEN mr_deadline ELSE compliance_deadline END) < NOW() + INTERVAL '5 days' THEN 'DUE_SOON'
             ELSE 'ON_TRACK'
           END AS urgency
    FROM deficiency_records
    WHERE UPPER(facility_accreditation_no) = UPPER(p_accreditation_no)
      AND status IN ('RTF', 'FOR_MR')
  ) d;

  RETURN COALESCE(result, '[]'::json);
END;
$function$;


-- =====================================================================
-- 9. STAFF: Review Refiled (kasama ang MR letter)
-- =====================================================================
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
  -- kapag may session token, ang server ang nagtatakda ng branch
  v_caller := _current_caller(ARRAY['ADMIN', 'BRANCH_ADMIN', 'STAFF', 'BAS']);
  IF v_caller.id IS NOT NULL THEN
    p_branch := CASE WHEN v_caller.role = 'ADMIN' THEN NULL ELSE COALESCE(v_caller.branch, '__NONE__') END;
  END IF;

  SELECT json_agg(row_to_json(d) ORDER BY d.refile_timestamp ASC) INTO result
  FROM (
    SELECT gatn_no, gacn_no, facility_accreditation_no, issue_category, specific_issue,
           refile_timestamp, refile_file_link, refile_notes, is_late_submission,
           is_mr_filing, mr_letter_link, mr_deadline
    FROM deficiency_records
    WHERE status = 'REFILED'
      AND (p_branch IS NULL OR p_branch = '' OR UPPER(pro_region) = UPPER(p_branch))
  ) d;

  RETURN COALESCE(result, '[]'::json);
END;
$function$;


-- =====================================================================
-- 10. STAFF: GAMOT Tracker at History (kasama ang MR deadline / denied date)
-- =====================================================================
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
      mr_deadline, denied_at
    FROM deficiency_records
    WHERE (p_branch IS NULL OR p_branch = '' OR UPPER(pro_region) = UPPER(p_branch))
  ) d;

  RETURN COALESCE(result, '[]'::json);
END;
$function$;


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
           mr_deadline, denied_at
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


-- =====================================================================
-- 11. ANALYTICS: dagdag na bilang ng FOR_MR at DENIED
-- =====================================================================
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
  -- kapag may session token, ang server ang nagtatakda ng branch
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
    'total_for_mr', COUNT(*) FILTER (WHERE status = 'FOR_MR'),
    'total_denied', COUNT(*) FILTER (WHERE status = 'DENIED'),
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
