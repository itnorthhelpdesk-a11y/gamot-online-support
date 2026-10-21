-- =====================================================================
-- 2026-10-21_07  Kasaysayan ng LAHAT ng attachments (refile at MR)
--
-- Dati: kapag nag-refile ulit ang pharmacy, PINAPALITAN ng bagong file ang
-- luma sa deficiency_records, kaya hindi na mabuksan ang naunang file.
-- Ngayon: bawat refile / MR ay itinatabi sa refile_submissions, kasama ang
-- notes, petsa, at resulta ng review (RESOLVED / RETURNED + dahilan).
-- Makikita ito ng PhilHealth staff sa History -> "📎 Files".
--
-- Ligtas patakbuhin bago i-deploy ang bagong index.html (walang binabago sa
-- mga dating function; trigger at bagong table/RPC lang ang idinadagdag).
-- Rollback: 2026-10-21_07_rollback.sql
-- =====================================================================

BEGIN;

-- 1) Table ng bawat submission
CREATE TABLE IF NOT EXISTS public.refile_submissions (
  id                        BIGSERIAL PRIMARY KEY,
  gatn_no                   TEXT NOT NULL,
  pro_region                TEXT,
  facility_accreditation_no TEXT,
  submitted_at              TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  submitted_by              TEXT,
  is_mr_filing              BOOLEAN NOT NULL DEFAULT FALSE,
  is_late_submission        BOOLEAN NOT NULL DEFAULT FALSE,
  refile_file_link          TEXT,
  mr_letter_link            TEXT,
  refile_notes              TEXT,
  review_result             TEXT,          -- NULL = hinihintay pa ang review; 'RESOLVED' o 'RETURNED'
  review_remarks            TEXT,
  reviewed_by               TEXT,
  reviewed_at               TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS refile_submissions_gatn_idx ON public.refile_submissions (gatn_no);
CREATE INDEX IF NOT EXISTS refile_submissions_file_idx ON public.refile_submissions (refile_file_link);
CREATE INDEX IF NOT EXISTS refile_submissions_mr_idx   ON public.refile_submissions (mr_letter_link);

-- Sa RPC at Edge Function lang dumadaan (walang direktang access mula sa browser)
ALTER TABLE public.refile_submissions ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON public.refile_submissions FROM anon, authenticated;

-- 2) Username ng naka-login (mula sa session token); NULL kung wala. Hindi nag-e-error.
CREATE OR REPLACE FUNCTION public._session_username()
RETURNS TEXT
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = public, extensions
AS $$
DECLARE
  v_token TEXT;
  v_username TEXT;
BEGIN
  BEGIN
    v_token := current_setting('request.headers', true)::JSON->>'x-egos-session';
  EXCEPTION WHEN others THEN
    RETURN NULL;
  END;

  IF v_token IS NULL OR v_token = '' THEN
    RETURN NULL;
  END IF;

  SELECT u.username INTO v_username
  FROM sessions s
  JOIN users u ON u.id = s.user_id
  WHERE s.token_hash = encode(digest(v_token, 'sha256'), 'hex');

  RETURN v_username;
END;
$$;
REVOKE ALL ON FUNCTION public._session_username() FROM PUBLIC, anon, authenticated;

-- 3) Trigger: itala ang bawat refile / MR at ang resulta ng review
CREATE OR REPLACE FUNCTION public._track_refile_submissions()
RETURNS TRIGGER
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, extensions
AS $$
BEGIN
  IF NEW.status = 'REFILED' AND NEW.refile_timestamp IS DISTINCT FROM OLD.refile_timestamp THEN
    -- Bagong refile o MR ng pharmacy
    INSERT INTO refile_submissions (gatn_no, pro_region, facility_accreditation_no, submitted_at, submitted_by,
                                    is_mr_filing, is_late_submission, refile_file_link, mr_letter_link, refile_notes)
    VALUES (NEW.gatn_no, NEW.pro_region, NEW.facility_accreditation_no, COALESCE(NEW.refile_timestamp, NOW()),
            _session_username(), COALESCE(NEW.is_mr_filing, FALSE), COALESCE(NEW.is_late_submission, FALSE),
            NEW.refile_file_link, CASE WHEN NEW.is_mr_filing THEN NEW.mr_letter_link END, NEW.refile_notes);

  ELSIF OLD.status = 'REFILED' AND NEW.status IS DISTINCT FROM 'REFILED' THEN
    -- Na-review: RESOLVED, o ibinalik para sa re-correction (RTF / FOR_MR)
    UPDATE refile_submissions
    SET review_result  = CASE WHEN NEW.status = 'RESOLVED' THEN 'RESOLVED' ELSE 'RETURNED' END,
        review_remarks = CASE WHEN NEW.status = 'RESOLVED' THEN NULL ELSE NEW.review_remarks END,
        reviewed_by    = COALESCE(_session_username(), CASE WHEN NEW.status = 'RESOLVED' THEN NEW.resolved_by END),
        reviewed_at    = NOW()
    WHERE id = (SELECT id FROM refile_submissions
                WHERE gatn_no = NEW.gatn_no AND review_result IS NULL
                ORDER BY submitted_at DESC LIMIT 1);
  END IF;

  RETURN NULL;
END;
$$;
REVOKE ALL ON FUNCTION public._track_refile_submissions() FROM PUBLIC, anon, authenticated;

DROP TRIGGER IF EXISTS deficiency_records_track_refiles ON public.deficiency_records;
CREATE TRIGGER deficiency_records_track_refiles
  AFTER UPDATE OF status, refile_timestamp ON public.deficiency_records
  FOR EACH ROW EXECUTE FUNCTION public._track_refile_submissions();

-- 4) Ilipat ang mga kasalukuyang attachment (huling submission ng bawat record)
INSERT INTO public.refile_submissions (gatn_no, pro_region, facility_accreditation_no, submitted_at, submitted_by,
                                       is_mr_filing, is_late_submission, refile_file_link, mr_letter_link, refile_notes,
                                       review_result, review_remarks, reviewed_by, reviewed_at)
SELECT r.gatn_no, r.pro_region, r.facility_accreditation_no, COALESCE(r.refile_timestamp, r.created_at),
       (SELECT a.performed_by_username FROM audit_trail a
        WHERE a.gatn_no = r.gatn_no AND a.action IN ('REFILE', 'MR_FILED')
        ORDER BY a.performed_at DESC LIMIT 1),
       COALESCE(r.is_mr_filing, FALSE), COALESCE(r.is_late_submission, FALSE),
       r.refile_file_link, CASE WHEN r.is_mr_filing THEN r.mr_letter_link END, r.refile_notes,
       CASE WHEN r.status = 'REFILED' THEN NULL WHEN r.status = 'RESOLVED' THEN 'RESOLVED' ELSE 'RETURNED' END,
       CASE WHEN r.status NOT IN ('REFILED', 'RESOLVED') THEN r.review_remarks END,
       CASE WHEN r.status = 'RESOLVED' THEN r.resolved_by
            WHEN r.status <> 'REFILED' THEN (SELECT a.performed_by_username FROM audit_trail a
                                             WHERE a.gatn_no = r.gatn_no AND a.action = 'RETURN_FOR_CORRECTION'
                                             ORDER BY a.performed_at DESC LIMIT 1) END,
       CASE WHEN r.status = 'RESOLVED' THEN r.resolved_timestamp
            WHEN r.status <> 'REFILED' THEN (SELECT a.performed_at FROM audit_trail a
                                             WHERE a.gatn_no = r.gatn_no AND a.action = 'RETURN_FOR_CORRECTION'
                                             ORDER BY a.performed_at DESC LIMIT 1) END
FROM public.deficiency_records r
WHERE r.refile_file_link IS NOT NULL
  AND NOT EXISTS (SELECT 1 FROM public.refile_submissions s WHERE s.gatn_no = r.gatn_no);

-- 5) RPC para sa History: lahat ng submission ng isang GATN (staff ng parehong branch; ADMIN = lahat)
CREATE OR REPLACE FUNCTION public.get_refile_submissions(p_gatn_no TEXT)
RETURNS JSON
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
  v_caller public.users;
  result JSON;
BEGIN
  v_caller := _current_caller(ARRAY['ADMIN', 'BRANCH_ADMIN', 'STAFF', 'BAS']);

  SELECT json_agg(row_to_json(t) ORDER BY t.submitted_at) INTO result
  FROM (
    SELECT id, submitted_at, submitted_by, is_mr_filing, is_late_submission,
           refile_file_link, mr_letter_link, refile_notes,
           review_result, review_remarks, reviewed_by, reviewed_at
    FROM refile_submissions
    WHERE gatn_no = UPPER(p_gatn_no)
      AND (v_caller.role = 'ADMIN' OR UPPER(pro_region) = UPPER(COALESCE(v_caller.branch, '__NONE__')))
  ) t;

  RETURN COALESCE(result, '[]'::json);
END;
$$;

COMMIT;

-- Pang-check (dapat may row ang bawat record na may attachment; 4 ngayon):
-- SELECT gatn_no, submitted_at, submitted_by, review_result, reviewed_by FROM refile_submissions ORDER BY submitted_at;
