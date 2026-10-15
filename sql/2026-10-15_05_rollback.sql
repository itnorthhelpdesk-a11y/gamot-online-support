-- =====================================================================
-- ROLLBACK para sa 2026-10-15_05_private_attachments.sql
-- Ibinabalik sa PUBLIC ang refile-attachments at registration-attachments
-- (gaya ng dati). Gamitin LAMANG kung hindi mabuksan ang mga attachment.
-- Ang EGOS bucket ay sinadyang HINDI ibinabalik sa public.
-- =====================================================================

BEGIN;

UPDATE storage.buckets SET public = true
WHERE id IN ('refile-attachments', 'registration-attachments');

CREATE POLICY "Allow public read of refile-attachments" ON storage.objects
  FOR SELECT TO public USING (bucket_id = 'refile-attachments');
CREATE POLICY "Allow public read of registration-attachments" ON storage.objects
  FOR SELECT TO public USING (bucket_id = 'registration-attachments');

COMMIT;
