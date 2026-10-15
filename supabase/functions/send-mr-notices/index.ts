import { createClient } from "https://esm.sh/@supabase/supabase-js@2";

// Tinatawag LAMANG ng pg_cron (sql/2026-10-15_04b_mr_schedule.sql) kada oras.
// Nagpapadala ng formal MR / Appeal notice sa LAHAT ng approved pharmacy
// accounts ng facility, at itinatala sa mr_notice_queue + audit_trail
// bilang patunay na na-inform ang facility.
//
// Kailangan sa Edge Function secrets: EGOS_CRON_SECRET (galing sa Vault)
// Sa Supabase dashboard: naka-OFF dapat ang "Enforce JWT verification".

const MAX_ATTEMPTS = 5;

function json(body: unknown, status = 200) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}

function formatDate(value: string | null) {
  if (!value) return "N/A";
  return new Date(value).toLocaleDateString("en-PH", {
    timeZone: "Asia/Manila", year: "numeric", month: "long", day: "numeric",
  });
}

Deno.serve(async (req) => {
  // Ang scheduled job lang ang puwedeng tumawag dito
  const expected = Deno.env.get("EGOS_CRON_SECRET") || "";
  const given = req.headers.get("x-egos-cron") || "";
  if (!expected || given !== expected) {
    return json({ success: false, error: "NOT_AUTHORIZED" }, 401);
  }

  const SUPABASE_SECRET_KEYS = JSON.parse(Deno.env.get("SUPABASE_SECRET_KEYS")!);
  const supabaseAdmin = createClient(
    Deno.env.get("SUPABASE_URL")!,
    SUPABASE_SECRET_KEYS["default"]
  );

  const { data: queue, error: queueError } = await supabaseAdmin
    .from("mr_notice_queue")
    .select("id, gatn_no, kind, attempts")
    .in("status", ["PENDING", "FAILED"])
    .lt("attempts", MAX_ATTEMPTS)
    .order("created_at", { ascending: true })
    .limit(50);

  if (queueError) return json({ success: false, error: queueError.message }, 500);

  const results = [];

  for (const item of queue || []) {
    const { data: rec } = await supabaseAdmin
      .from("deficiency_records")
      .select("gatn_no, gacn_no, facility, facility_accreditation_no, specific_issue, pro_region, rtf_date, compliance_deadline, mr_deadline, status")
      .eq("gatn_no", item.gatn_no)
      .maybeSingle();

    // Wala na ang record o hindi na FOR_MR (hal. na-refile na) — hindi na kailangang ipadala
    if (!rec || rec.status !== "FOR_MR") {
      await supabaseAdmin.from("mr_notice_queue")
        .update({ status: "SENT", error: "Skipped: record is no longer FOR_MR.", sent_at: new Date().toISOString() })
        .eq("id", item.id);
      results.push({ gatn: item.gatn_no, status: "SKIPPED" });
      continue;
    }

    // LAHAT ng approved pharmacy accounts ng parehong accreditation
    const { data: users } = await supabaseAdmin
      .from("users")
      .select("username, email")
      .eq("account_type", "PHARMACY")
      .eq("status", "APPROVED")
      .eq("accreditation_no", rec.facility_accreditation_no);

    const recipients = Array.from(new Set((users || [])
      .map((u: any) => String(u.email || "").trim())
      .filter((e: string) => e.includes("@"))));

    if (recipients.length === 0) {
      await supabaseAdmin.from("mr_notice_queue")
        .update({ status: "NO_RECIPIENT", attempts: item.attempts + 1, error: "No approved pharmacy account with an email for " + rec.facility_accreditation_no + "." })
        .eq("id", item.id);
      await supabaseAdmin.from("audit_trail").insert({
        gatn_no: rec.gatn_no, action: "MR_NOTICE_NOT_SENT", branch: rec.pro_region, performed_by_username: "SYSTEM",
        details: "No registered pharmacy account with an email for accreditation " + rec.facility_accreditation_no +
                 ". Please notify the facility manually. MR deadline: " + formatDate(rec.mr_deadline) + ".",
      });
      results.push({ gatn: rec.gatn_no, status: "NO_RECIPIENT" });
      continue;
    }

    const reopened = item.kind === "REOPENED";
    const subject = "NOTICE: GAMOT Claim Deficiency " +
      (reopened ? "Reopened for" : "Now Under") +
      " Motion for Reconsideration / Appeal Period – GATN " + rec.gatn_no;

    const body =
      `Dear ${rec.facility || "Facility"},\n\n` +
      (reopened
        ? `This is to formally inform you that the previously DENIED claim below has been REOPENED by PhilHealth for Motion for Reconsideration / Appeal:\n\n`
        : `This is to formally inform you that the deficiency for the claim below was NOT complied with within the 60-day compliance period:\n\n`) +
      `GATN No.: ${rec.gatn_no}\n` +
      `GACN No.: ${rec.gacn_no || "N/A"}\n` +
      `Issue: ${rec.specific_issue || "N/A"}\n` +
      `Return-to-Facility (RTF) date: ${formatDate(rec.rtf_date)}\n` +
      `Original compliance deadline: ${formatDate(rec.compliance_deadline)}\n\n` +
      `You are given until ${formatDate(rec.mr_deadline)} to file a Motion for Reconsideration / Appeal. ` +
      `To do so, log in to Easy GAMOT Online Support, open Refile Deficiency, upload the corrected documents, and attach your MR letter.\n\n` +
      `IF NO MOTION FOR RECONSIDERATION / APPEAL IS FILED ON OR BEFORE ${formatDate(rec.mr_deadline).toUpperCase()}, ` +
      `THE CLAIM WILL BE DENIED WITH FINALITY AND CAN NO LONGER BE REFILED.\n\n` +
      `This notice was sent to all registered accounts of your facility.\n\n` +
      `PhilHealth Regional Office – ${rec.pro_region || ""}\n` +
      `Easy GAMOT Online Support`;

    const sentTo: string[] = [];
    const failed: string[] = [];
    for (const to of recipients) {
      const r = await sendEmailWithFallback(to, subject, body);
      if (r.success) sentTo.push(to); else failed.push(to + " (" + (r.error || "error") + ")");
    }

    const status = failed.length === 0 ? "SENT" : (sentTo.length > 0 ? "PARTIAL" : "FAILED");

    await supabaseAdmin.from("mr_notice_queue").update({
      status,
      attempts: item.attempts + 1,
      recipients: sentTo.join(", "),
      error: failed.length ? failed.join("; ") : null,
      sent_at: sentTo.length ? new Date().toISOString() : null,
    }).eq("id", item.id);

    if (sentTo.length > 0) {
      await supabaseAdmin.from("audit_trail").insert({
        gatn_no: rec.gatn_no, action: "MR_NOTICE_SENT", branch: rec.pro_region, performed_by_username: "SYSTEM",
        details: (reopened ? "Reopen notice" : "MR / Appeal notice") + " emailed to: " + sentTo.join(", ") +
                 ". MR deadline: " + formatDate(rec.mr_deadline) + "." +
                 (failed.length ? " FAILED for: " + failed.join("; ") : ""),
      });
    }

    results.push({ gatn: rec.gatn_no, status, sent: sentTo.length, failed: failed.length });
  }

  return json({ success: true, processed: results.length, results });
});

const GMAIL_SCRIPT_URL = "https://script.google.com/macros/s/AKfycbzI96QehmDTjIO54SpQrtPxOdyODxj9feCSwmALqCTXfk6PiVdGCLapiC_VCiomC_HnZg/exec";

async function sendEmailWithFallback(to: string, subject: string, text: string) {
  try {
    const res = await fetch(GMAIL_SCRIPT_URL, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ to, subject, body: text })
    });
    const result = await res.json();
    if (result.success) return { success: true, method: "GMAIL" };
  } catch (e) {}

  try {
    const res = await fetch("https://api.brevo.com/v3/smtp/email", {
      method: "POST",
      headers: {
        "api-key": Deno.env.get("BREVO_API_KEY")!,
        "Content-Type": "application/json",
        "accept": "application/json"
      },
      body: JSON.stringify({
        sender: { name: "EYOS Support Team", email: "itnorthhelpdesk@gmail.com" },
        to: [{ email: to }],
        subject,
        textContent: text
      })
    });
    if (res.ok) return { success: true, method: "BREVO" };
    return { success: false, error: await res.text() };
  } catch (e) {
    return { success: false, error: e.message };
  }
}
