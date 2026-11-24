-- =====================================================================
-- EGOS: Itama ang Facility ng isang record ng P92039188
-- Petsa: 2026-11-24
--
-- PROBLEMA: may isang deficiency record ng P92039188 na GACN number
--   ("GACN01016826") ang na-type sa Facility imbes na pangalan.
--   Ang 202 na ibang record nila ay "CGD MEDICAL DEPOT INC".
--
-- ANO ANG GINAGAWA:
--   - Facility lang ang pinapalitan; walang ibang field na ginagalaw.
--   - Isang record lang. Kapag hindi eksaktong 1 ang tumugma, hihinto
--     ito at WALANG babaguhin.
--   - Nag-iiwan ng entry sa audit_trail (action EDIT) para makita sa Trail.
--
-- BAGO I-RUN: palitan ang v_admin ng SARILI MONG EGOS username
--   (ito ang lalabas sa Trail bilang gumawa ng pagbabago).
--
-- ROLLBACK: 2026-11-24_15_rollback.sql
-- =====================================================================

DO $$
DECLARE
  v_admin   TEXT := 'ADMIN01';
  v_accred  TEXT := 'P92039188';
  v_wrong   TEXT := 'GACN01016826';
  v_correct TEXT := 'CGD MEDICAL DEPOT INC';
  v_count   INT;
  v_gatn    TEXT;
  v_branch  TEXT;
BEGIN
  IF v_admin = 'PALITAN_NG_USERNAME_MO' OR NULLIF(TRIM(v_admin), '') IS NULL THEN
    RAISE EXCEPTION 'Ilagay muna ang sarili mong EGOS username sa v_admin. Walang binago.';
  END IF;

  SELECT COUNT(*) INTO v_count
  FROM deficiency_records
  WHERE facility_accreditation_no = v_accred AND facility = v_wrong;

  IF v_count <> 1 THEN
    RAISE EXCEPTION 'Inaasahang 1 record, pero % ang nakita. Walang binago.', v_count;
  END IF;

  UPDATE deficiency_records
  SET facility = v_correct
  WHERE facility_accreditation_no = v_accred AND facility = v_wrong
  RETURNING gatn_no, pro_region INTO v_gatn, v_branch;

  PERFORM log_audit_trail(
    p_gatn_no  => UPPER(v_gatn),
    p_action   => 'EDIT',
    p_username => UPPER(v_admin),
    p_branch   => v_branch,
    p_details  => 'Facility corrected: "' || v_wrong || '" -> "' || v_correct || '" (GACN number was typed in the Facility field).'
  );

  RAISE NOTICE 'Naitama ang Facility ng GATN %.', v_gatn;
END $$;
