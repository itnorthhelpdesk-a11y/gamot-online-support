-- =====================================================================
-- EGOS Hakbang 4d: datos para sa Appeal Notice (PDF)
-- Petsa: 2026-10-15
--
-- get_appeal_notice(p_gatn_no): ibinabalik ang detalye ng GATN para sa
-- electronic na Appeal Notice. Para lang sa record na dumaan na sa MR
-- (may mr_notice_at).
--   - Pharmacy (USER / PHARMACY_ADMIN): sariling accreditation lang
--   - PhilHealth staff: sariling branch lang (ADMIN = lahat)
--
-- LIGTAS PATAKBUHIN KAHIT KAILAN (bagong function lang).
-- ROLLBACK: DROP FUNCTION public.get_appeal_notice(text);
-- =====================================================================

BEGIN;

CREATE OR REPLACE FUNCTION public.get_appeal_notice(p_gatn_no text)
 RETURNS json
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path = public, extensions
AS $function$
DECLARE
  v_caller public.users;
  v_rec RECORD;
BEGIN
  v_caller := _current_caller(ARRAY['USER', 'PHARMACY_ADMIN', 'ADMIN', 'BRANCH_ADMIN', 'STAFF', 'BAS']);

  SELECT gatn_no, gacn_no, facility, facility_accreditation_no, pro_region,
         issue_category, specific_issue, required_resolution, status,
         rtf_date, compliance_deadline, mr_notice_at, mr_deadline, denied_at
  INTO v_rec
  FROM deficiency_records
  WHERE gatn_no = UPPER(p_gatn_no);

  IF NOT FOUND OR v_rec.mr_notice_at IS NULL THEN
    RETURN json_build_object('success', false, 'message', 'No Motion for Reconsideration / Appeal notice exists for this GATN.');
  END IF;

  IF v_caller.account_type = 'PHARMACY' THEN
    IF UPPER(v_rec.facility_accreditation_no) IS DISTINCT FROM UPPER(COALESCE(v_caller.accreditation_no, '__NONE__')) THEN
      RETURN json_build_object('success', false, 'message', 'This GATN does not belong to your facility.');
    END IF;
  ELSIF v_caller.role <> 'ADMIN'
        AND UPPER(v_rec.pro_region) IS DISTINCT FROM UPPER(COALESCE(v_caller.branch, '__NONE__')) THEN
    RETURN json_build_object('success', false, 'message', 'Not authorized for this record.');
  END IF;

  RETURN json_build_object(
    'success', true,
    'gatn_no', v_rec.gatn_no,
    'gacn_no', v_rec.gacn_no,
    'facility', v_rec.facility,
    'facility_accreditation_no', v_rec.facility_accreditation_no,
    'pro_region', v_rec.pro_region,
    'issue_category', v_rec.issue_category,
    'specific_issue', v_rec.specific_issue,
    'required_resolution', v_rec.required_resolution,
    'status', v_rec.status,
    'rtf_date', v_rec.rtf_date,
    'compliance_deadline', v_rec.compliance_deadline,
    'mr_notice_at', v_rec.mr_notice_at,
    'mr_deadline', v_rec.mr_deadline,
    'denied_at', v_rec.denied_at
  );
END;
$function$;

COMMIT;
