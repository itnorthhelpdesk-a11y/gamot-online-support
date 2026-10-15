-- =====================================================================
-- EGOS TEST: pabilisin ang MR / Appeal process para sa TESTEGOS records LANG
-- (para hindi maghintay ng 60 araw). HINDI ginagalaw ang totoong records.
--
-- Patakbuhin ang bawat HAKBANG nang HIWALAY, ayon sa test steps.
-- =====================================================================

-- ---------- HAKBANG A: gawing lampas 60 araw ang RTF test records, tapos ilipat sa FOR_MR ----------
UPDATE deficiency_records
SET rtf_date = NOW() - INTERVAL '61 days',
    compliance_deadline = NOW() - INTERVAL '1 day'
WHERE gatn_no ILIKE 'TESTEGOS%' AND status = 'RTF';

SELECT public.process_mr_deadlines();

SELECT gatn_no, status, mr_deadline FROM deficiency_records WHERE gatn_no ILIKE 'TESTEGOS%' ORDER BY gatn_no;


-- ---------- HAKBANG B: gawing lampas na rin ang MR deadline, tapos ilipat sa DENIED ----------
-- (para lang sa FOR_MR test records na HINDI pa nag-file ng MR)
-- UPDATE deficiency_records
-- SET mr_deadline = NOW() - INTERVAL '1 day'
-- WHERE gatn_no ILIKE 'TESTEGOS%' AND status = 'FOR_MR';
--
-- SELECT public.process_mr_deadlines();
--
-- SELECT gatn_no, status, denied_at FROM deficiency_records WHERE gatn_no ILIKE 'TESTEGOS%' ORDER BY gatn_no;
