-- =====================================================================
-- EGOS Hakbang 4b: I-ON ang awtomatikong MR / Appeal schedule
-- Petsa: 2026-10-15
--
-- *** PATAKBUHIN LAMANG KAPAG ***
--   1. Napatakbo na ang 2026-10-15_04_mr_appeal.sql, AT
--   2. Na-deploy na ang Edge Function na send-mr-notices, AT
--   3. Na-merge at live na ang bagong index.html.
--
-- ANO ANG GINAGAWA:
--   - Ine-enable ang pg_cron (schedule) at pg_net (tawag sa Edge Function)
--   - Gumagawa ng random na secret sa Vault (egos_cron_secret) para ang
--     scheduled job lang ang makakatawag sa send-mr-notices
--   - Kada oras (minuto :05): process_mr_deadlines() + padala ng notices
--
-- PAGKATAPOS PATAKBUHIN: kopyahin ang secret papunta sa Edge Function
-- secrets bilang EGOS_CRON_SECRET (tingnan ang query sa ibaba ng file).
--
-- PARA I-OFF:  SELECT cron.unschedule('egos-mr-deadlines');
-- =====================================================================

CREATE EXTENSION IF NOT EXISTS pg_cron;
CREATE EXTENSION IF NOT EXISTS pg_net;

-- Random na secret (isang beses lang ginagawa)
SELECT vault.create_secret(encode(extensions.gen_random_bytes(32), 'hex'), 'egos_cron_secret',
  'Shared secret: pg_cron -> send-mr-notices Edge Function')
WHERE NOT EXISTS (SELECT 1 FROM vault.secrets WHERE name = 'egos_cron_secret');

-- Kada oras sa minuto :05
SELECT cron.schedule(
  'egos-mr-deadlines',
  '5 * * * *',
  $job$
    SELECT public.process_mr_deadlines();
    SELECT net.http_post(
      url := 'https://ukdiibumagfqngqkqmom.supabase.co/functions/v1/send-mr-notices',
      headers := jsonb_build_object(
        'Content-Type', 'application/json',
        'x-egos-cron', (SELECT decrypted_secret FROM vault.decrypted_secrets WHERE name = 'egos_cron_secret')
      ),
      body := '{}'::jsonb
    );
  $job$
);

-- Pag-check: dapat may 1 row na 'egos-mr-deadlines'
SELECT jobid, jobname, schedule, active FROM cron.job WHERE jobname = 'egos-mr-deadlines';

-- ---------- KOPYAHIN ANG SECRET (patakbuhin nang hiwalay) ----------
-- SELECT decrypted_secret FROM vault.decrypted_secrets WHERE name = 'egos_cron_secret';
-- Ilagay ang resulta sa: Edge Functions -> Secrets -> EGOS_CRON_SECRET
