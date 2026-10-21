-- =====================================================================
-- ROLLBACK para sa 2026-10-21_07_refile_submissions.sql
-- BABALA: mabubura ang kasaysayan ng mga submission (refile_submissions).
-- Ang mga file mismo sa Storage at ang huling attachment sa
-- deficiency_records ay HINDI nagagalaw.
-- Ibalik muna ang dating index.html at get-file-url bago ito patakbuhin.
-- =====================================================================

BEGIN;

DROP TRIGGER IF EXISTS deficiency_records_track_refiles ON public.deficiency_records;
DROP FUNCTION IF EXISTS public._track_refile_submissions();
DROP FUNCTION IF EXISTS public.get_refile_submissions(TEXT);
DROP FUNCTION IF EXISTS public._session_username();
DROP TABLE IF EXISTS public.refile_submissions;

COMMIT;
