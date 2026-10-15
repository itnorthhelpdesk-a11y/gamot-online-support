-- =====================================================================
-- EGOS Hakbang 5: GAWING PRIVATE ANG MGA ATTACHMENT
-- Petsa: 2026-10-15
--
-- *** PATAKBUHIN LAMANG KAPAG ***
--   1. Na-deploy na ang Edge Function na get-file-url (JWT verification OFF), AT
--   2. Na-merge at live na ang bagong index.html (mga "View" link na
--      dumadaan sa get-file-url).
-- Kapag pinatakbo ito nang mas maaga, HINDI mabubuksan ng staff/pharmacy
-- ang mga attachment sa lumang page (pero walang file na mawawala).
--
-- ANO ANG GINAGAWA:
--   refile-attachments, registration-attachments:
--     - private na ang bucket (hindi na gumagana ang public link)
--     - tinatanggal ang "public read" policy
--     - NANANATILI ang "public upload" (kailangan sa registration at refile)
--   EGOS (lumang bucket, hindi na ginagamit ng page; may 2 PDF):
--     - private na, at tinatanggal ang public read/upload/update/delete
--     - HINDI binubura ang mga file
--   document-templates: HINDI ginagalaw (blangkong NDA forms; public dapat)
--
-- ROLLBACK: 2026-10-15_05_rollback.sql
-- =====================================================================

BEGIN;

UPDATE storage.buckets SET public = false
WHERE id IN ('refile-attachments', 'registration-attachments', 'EGOS');

DROP POLICY IF EXISTS "Allow public read of refile-attachments" ON storage.objects;
DROP POLICY IF EXISTS "Allow public read of registration-attachments" ON storage.objects;

DROP POLICY IF EXISTS "Public insert access for EGOS bucket 19kp2_0" ON storage.objects;
DROP POLICY IF EXISTS "Public insert access for EGOS bucket 19kp2_1" ON storage.objects;
DROP POLICY IF EXISTS "Public insert access for EGOS bucket 19kp2_2" ON storage.objects;
DROP POLICY IF EXISTS "Public insert access for EGOS bucket 19kp2_3" ON storage.objects;

COMMIT;

-- Pag-check: dapat public = false ang 3 bucket, at 2 INSERT policy na lang ang natira
SELECT id, public FROM storage.buckets ORDER BY id;
SELECT policyname, cmd FROM pg_policies WHERE schemaname = 'storage' AND tablename = 'objects' ORDER BY policyname;
