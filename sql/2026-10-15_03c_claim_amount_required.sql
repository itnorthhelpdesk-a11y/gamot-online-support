-- =====================================================================
-- EGOS Hakbang 3c: REQUIRED ang Claim Amount sa encode
-- Petsa: 2026-10-15
--
-- Dati: puwedeng mag-encode nang walang Claim Amount (NULL).
-- Ngayon: tatanggihan ng server kapag walang laman o 0 / negatibo.
-- (May "required" na rin ang field sa index.html.)
--
-- LIGTAS PATAKBUHIN KAHIT KAILAN (parehong parameters). Sa lumang
-- index.html, lalabas lang ang mensahe kapag walang amount.
-- ROLLBACK: patakbuhin ulit ang 2026-10-15_03_otp_audit_idno.sql
--           (bahagi 4 lang ang kailangan: encode_deficiency)
-- =====================================================================

BEGIN;
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

  -- BAGO (3c): required ang Claim Amount (dapat higit sa 0)
  IF p_claim_amount IS NULL OR p_claim_amount <= 0 THEN
    RETURN json_build_object('success', false, 'message', 'Claim Amount is required and must be greater than zero.');
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
