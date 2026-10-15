import { createClient } from "https://esm.sh/@supabase/supabase-js@2";

// BAGO: kasama na ang x-egos-session sa allowed headers (session token ng EGOS)
const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type, x-egos-session",
};

// BAGO: kapag "true" ang secret na ito, REQUIRED ang session token.
// Habang hindi pa naka-set, gumagana pa rin ang lumang index.html (walang token).
const REQUIRE_SESSION = Deno.env.get("EGOS_REQUIRE_SESSION") === "true";

// BAGO: kunin ang naka-login na user mula sa session token (parehong rules ng _current_caller sa SQL)
async function getSessionUser(req: Request, supabaseAdmin: any) {
  const token = req.headers.get("x-egos-session") || "";
  if (!token) return { present: false, user: null };

  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(token));
  const hash = Array.from(new Uint8Array(digest)).map((b) => b.toString(16).padStart(2, "0")).join("");

  const { data: session } = await supabaseAdmin
    .from("sessions")
    .select("user_id, expires_at, last_seen_at, revoked_at")
    .eq("token_hash", hash)
    .maybeSingle();

  const now = Date.now();
  if (!session || session.revoked_at
      || new Date(session.expires_at).getTime() <= now
      || new Date(session.last_seen_at).getTime() <= now - 2 * 60 * 60 * 1000) {
    return { present: true, user: null };
  }

  const { data: user } = await supabaseAdmin
    .from("users")
    .select("id, username, role, branch, accreditation_no, account_type, facility, status")
    .eq("id", session.user_id)
    .maybeSingle();

  if (!user || user.status !== "APPROVED") return { present: true, user: null };

  await supabaseAdmin.from("sessions").update({ last_seen_at: new Date().toISOString() }).eq("token_hash", hash);
  return { present: true, user };
}

const KNOWLEDGE_BASE = `
You are the "Ask AI" help assistant for Easy GAMOT Online Support (EGOS/GAMOT), a system used by PhilHealth staff and GAMOT pharmacies/facilities to track and resolve GAMOT deficiency claims.

IMPORTANT RULES:
- Only answer questions about HOW TO USE the system, based ONLY on the information below.
- NEVER answer questions about specific patients, claims, GATN numbers, or any real data — you have no access to the database.
- NEVER invent features that are not listed below.
- If asked something outside this scope, politely say you can't help with that and suggest contacting their Branch Admin, Pharmacy Admin, or Super Admin.
- Keep answers short, clear, and friendly. Use simple steps when explaining how to do something.
- Answer in the same language the user asks in (Filipino/Taglish or English).

SYSTEM OVERVIEW:
GAMOT connects PhilHealth staff and accredited GAMOT pharmacies for encoding, refiling, reviewing, and tracking claim deficiencies.

ROLES:
- GAMOT Facility/Pharmacy: refiles corrected documents, tracks own history.
- PhilHealth Staff (GAMOT Processor): encodes deficiencies, reviews/resolves refiles, monitors compliance.
- PhilHealth Staff (Accounting): tracks claim amounts/payment status; can only encode for internal tracking (not send to pharmacy).
- Branch Admin: same as staff, plus approves accounts for their branch.
- Super Admin: full access across all branches, manages Branch Admins.
- Pharmacy Admin: first approved staff of a facility; approves other staff of same facility.

REGISTRATION: Choose account type (Pharmacy or PhilHealth Staff) -> fill required fields -> verify email (6-digit code) -> password needs 8+ chars with uppercase, lowercase, number -> upload supporting document(s), up to 5 files merged into one PDF -> submit -> wait for Admin approval.

LOGIN: username + password. 5 wrong attempts = 15 min lockout. "Forgot Password?" sends a reset code to registered email. Sessions auto-logout after inactivity.

PHARMACY FEATURES:
- Refile Deficiency: search GATN, review issue, upload corrected document(s) (merged into 1 PDF), submit. Refiling past the 60-day deadline is accepted but flagged LATE.
- My Deficiencies: shows urgency - OVERDUE (past deadline), DUE SOON, ON TRACK.
- History: full facility history with filters and Excel export.
- Pharmacy Admin only: Pending Staff (approve/decline), My Staff (edit email/PIN, reset password, deactivate).

PHILHEALTH STAFF FEATURES:
- Home/Encode: encode new deficiency. Optional AI Auto-fill (upload 1-2 photos of GAMOT Prescription/Availment Slip, AI pre-fills fields except Issue Category/Specific Issue). Preview before saving. Choose "Send to Pharmacy (RTF)" or "Save to Tracker Only (Processing)". Accounting staff can only save as Processing.
- History: system-wide records, filters, edit/delete (logged in Trail).
- Review Refiled Submissions: Mark Resolved or Request Re-correction (with required reason). Has search by GATN and date filter.
- Compliance Monitoring: % resolved per GACN batch.
- GAMOT Tracker: consolidated reporting view matching external report columns. Toggle Paid/Unpaid. Edit Remarks/Action Taken/Date Processed without changing true system status. Overdue filter. Excel export.
- Analytics Dashboard: summary stats and charts (category, status, monthly trend, branch comparison for Super Admin).
- Trail: full audit history per GATN, plus Account Approvals log.
- Delete History: browsable list of deleted records.
- Manage Accounts (Admin/Branch Admin): view Staff or Pharmacy accounts, edit details, reset password, deactivate, promote/revoke Branch Admin (Super Admin only).

SECURITY: Passwords are hashed (nobody can see them, not even admins). Emails must be verified and unique. Rate limiting prevents brute-force login attempts and spam registrations. Session auto-timeout. Full audit trail of all actions. Facilities can only see their own data. Daily automatic backups.
`;

Deno.serve(async (req) => {
  if (req.method === "OPTIONS") {
    return new Response("ok", { headers: corsHeaders });
  }

  try {
    const body = await req.json();
    const { message, history } = body;

    const SUPABASE_SECRET_KEYS = JSON.parse(Deno.env.get("SUPABASE_SECRET_KEYS")!);
    const supabaseAdmin = createClient(
      Deno.env.get("SUPABASE_URL")!,
      SUPABASE_SECRET_KEYS["default"]
    );

    // BAGO: ang username para sa daily limit ay galing sa session, hindi sa browser
    const session = await getSessionUser(req, supabaseAdmin);
    if ((session.present || REQUIRE_SESSION) && !session.user) {
      return new Response(JSON.stringify({ success: false, error: "SESSION_EXPIRED" }), {
        status: 401,
        headers: { ...corsHeaders, "Content-Type": "application/json" }
      });
    }
    const username = session.user ? session.user.username : body.username;

    if (!username || !message) {
      return new Response(JSON.stringify({ success: false, error: "Missing username or message." }), {
        status: 400,
        headers: { ...corsHeaders, "Content-Type": "application/json" }
      });
    }

    const oneDayAgo = new Date(Date.now() - 24 * 60 * 60 * 1000).toISOString();
    const { data: recentRequests } = await supabaseAdmin
      .from("ai_chat_requests")
      .select("id")
      .eq("username", username.toUpperCase())
      .gte("created_at", oneDayAgo);

    if (recentRequests && recentRequests.length >= 20) {
      return new Response(JSON.stringify({ success: false, error: "You've reached today's limit for Ask AI questions. Please try again tomorrow, or contact your Admin for help." }), {
        status: 429,
        headers: { ...corsHeaders, "Content-Type": "application/json" }
      });
    }

    await supabaseAdmin.from("ai_chat_requests").insert({ username: username.toUpperCase() });

    const GEMINI_API_KEY = Deno.env.get("GEMINI_API_KEY");

    const contents = [];
    const trimmedHistory = (history || []).slice(-6);
    trimmedHistory.forEach(function(h: any) {
      contents.push({ role: h.role === "user" ? "user" : "model", parts: [{ text: h.text }] });
    });
    contents.push({ role: "user", parts: [{ text: message }] });

    const response = await fetch(
      "https://generativelanguage.googleapis.com/v1beta/models/gemini-3.1-flash-lite:generateContent?key=" + GEMINI_API_KEY,
      {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          systemInstruction: { parts: [{ text: KNOWLEDGE_BASE }] },
          contents: contents,
          generationConfig: { maxOutputTokens: 500 }
        })
      }
    );

    const result = await response.json();

    if (!response.ok) {
      return new Response(JSON.stringify({ success: false, error: result.error?.message || "AI service error." }), {
        status: 500,
        headers: { ...corsHeaders, "Content-Type": "application/json" }
      });
    }

    const answer = result.candidates?.[0]?.content?.parts?.[0]?.text || "Sorry, I couldn't generate a response. Please try rephrasing your question.";

    return new Response(JSON.stringify({ success: true, answer: answer }), {
      headers: { ...corsHeaders, "Content-Type": "application/json" }
    });
  } catch (e) {
    return new Response(JSON.stringify({ success: false, error: e.message }), {
      status: 500,
      headers: { ...corsHeaders, "Content-Type": "application/json" }
    });
  }
});
