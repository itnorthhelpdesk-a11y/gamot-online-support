-- ROLLBACK ng 2026-11-24_14_rtf_signature_gas.sql
-- Tinatanggal lang ang idinagdag na specific issue.
-- Paalala: hindi nito ginagalaw ang deficiency records na gumamit na nito.

DELETE FROM deficiency_resolution_guide
WHERE issue_category ILIKE '%SIGNATURE%'
  AND specific_issue = 'Justification or reason of unable to sign in GAS';
