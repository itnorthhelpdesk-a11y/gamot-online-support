-- ROLLBACK ng 2026-11-24_15_fix_facility_p92039188.sql
-- Ibinabalik ang Facility sa dati ("GACN01016826") at nagla-log din sa audit_trail.
-- Palitan muna ang v_admin at v_gatn (makikita ang GATN sa NOTICE ng fix o sa Trail).

DO $$
DECLARE
  v_admin  TEXT := 'PALITAN_NG_USERNAME_MO';
  v_gatn   TEXT := 'PALITAN_NG_GATN';
  v_branch TEXT;
BEGIN
  IF v_admin = 'PALITAN_NG_USERNAME_MO' OR v_gatn = 'PALITAN_NG_GATN' THEN
    RAISE EXCEPTION 'Ilagay muna ang v_admin at v_gatn. Walang binago.';
  END IF;

  UPDATE deficiency_records
  SET facility = 'GACN01016826'
  WHERE gatn_no = UPPER(v_gatn) AND facility_accreditation_no = 'P92039188' AND facility = 'CGD MEDICAL DEPOT INC'
  RETURNING pro_region INTO v_branch;

  IF NOT FOUND THEN
    RAISE EXCEPTION 'Walang tumugmang record. Walang binago.';
  END IF;

  PERFORM log_audit_trail(
    p_gatn_no  => UPPER(v_gatn),
    p_action   => 'EDIT',
    p_username => UPPER(v_admin),
    p_branch   => v_branch,
    p_details  => 'Rollback: Facility set back to "GACN01016826".'
  );
END $$;
