-- =====================================================================
-- EGOS: Bagong RTF reason
--   Issue Category : Signature
--   Specific Issue : Justification or reason of unable to sign in GAS
-- Petsa: 2026-11-24
--
-- HAKBANG 1 (silipin muna): patakbuhin ito para makita ang eksaktong
-- pangalan ng Signature category na gamit na sa EGOS.
--
--   SELECT issue_category, specific_issue, required_resolution
--   FROM deficiency_resolution_guide
--   WHERE issue_category ILIKE '%SIGN%'
--   ORDER BY issue_category, specific_issue;
--
-- HAKBANG 2: patakbuhin ang DO block sa ibaba.
--   - Ginagamit nito ang Signature category na nandiyan na (para hindi
--     magkaroon ng dalawang "Signature" sa dropdown).
--   - Kung wala pang Signature category, gagawa ito ng "SIGNATURE".
--   - Hindi ito magdadagdag kung nandiyan na ang parehong specific issue.
--   - Kapag dalawa o higit pa ang category na may "SIGNATURE" sa pangalan,
--     hihinto ito at walang idadagdag; sabihin mo sa akin kung alin ang gagamitin.
--
-- Walang kailangang baguhin sa index.html: lalabas agad sa dropdown
-- ng Encode pagka-refresh ng page.
--
-- ROLLBACK: 2026-11-24_14_rollback.sql
-- =====================================================================

DO $$
DECLARE
  v_category TEXT;
  v_count INT;
  v_issue TEXT := 'Justification or reason of unable to sign in GAS';
  v_resolution TEXT := 'Submit a written justification stating the reason the claimant was unable to sign the GAS, signed by the claimant''s authorized representative or the pharmacist-in-charge.';
BEGIN
  SELECT COUNT(DISTINCT issue_category) INTO v_count
  FROM deficiency_resolution_guide
  WHERE issue_category ILIKE '%SIGNATURE%';

  IF v_count > 1 THEN
    RAISE EXCEPTION 'Higit sa isang Signature category ang nakita. Walang idinagdag. Patakbuhin ang HAKBANG 1 at piliin kung alin.';
  END IF;

  SELECT issue_category INTO v_category
  FROM deficiency_resolution_guide
  WHERE issue_category ILIKE '%SIGNATURE%'
  LIMIT 1;

  v_category := COALESCE(v_category, 'SIGNATURE');

  IF EXISTS (
    SELECT 1 FROM deficiency_resolution_guide
    WHERE issue_category = v_category AND UPPER(specific_issue) = UPPER(v_issue)
  ) THEN
    RAISE NOTICE 'Nandiyan na ang "%" sa category "%". Walang idinagdag.', v_issue, v_category;
    RETURN;
  END IF;

  INSERT INTO deficiency_resolution_guide (issue_category, specific_issue, required_resolution)
  VALUES (v_category, v_issue, v_resolution);

  RAISE NOTICE 'Naidagdag sa category "%".', v_category;
END $$;
