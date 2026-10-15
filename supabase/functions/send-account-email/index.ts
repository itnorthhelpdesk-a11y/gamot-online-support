import { createClient } from "https://esm.sh/@supabase/supabase-js@2";

// BAGO: kasama na ang x-egos-session sa allowed headers (session token ng EGOS)
const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type, x-egos-session",
};

// BAGO: kapag "true" ang secret na ito, REQUIRED ang session token.
// Habang hindi pa naka-set, gumagana pa rin ang lumang index.html (walang token).
const REQUIRE_SESSION = Deno.env.get("EGOS_REQUIRE_SESSION") === "true";

function json(body: unknown, status = 200) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { ...corsHeaders, "Content-Type": "application/json" },
  });
}

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

Deno.serve(async (req) => {
  if (req.method === "OPTIONS") {
    return new Response("ok", { headers: corsHeaders });
  }

  try {
    // BAGO: username lang ang kinukuha sa browser; ang decision at reason ay galing sa database
    const { username } = await req.json();

    const SUPABASE_SECRET_KEYS = JSON.parse(Deno.env.get("SUPABASE_SECRET_KEYS")!);

    const supabaseAdmin = createClient(
      Deno.env.get("SUPABASE_URL")!,
      SUPABASE_SECRET_KEYS["default"]
    );

    const session = await getSessionUser(req, supabaseAdmin);
    if ((session.present || REQUIRE_SESSION) && !session.user) {
      return json({ success: false, error: "SESSION_EXPIRED" }, 401);
    }

    const { data: user, error: fetchError } = await supabaseAdmin
      .from("users")
      .select("username, email, id_no, facility, branch, status, decline_reason")
      .eq("username", String(username || "").toUpperCase())
      .single();

    if (fetchError || !user || !user.email) {
      return json({ success: false, error: "User email not found" }, 400);
    }

    // BAGO: Admin / Branch Admin (sariling branch) lang ang puwedeng mag-trigger ng email
    if (session.user) {
      const caller = session.user;
      const allowed = caller.role === "ADMIN"
        || (caller.role === "BRANCH_ADMIN" && String(caller.branch || "").toUpperCase() === String(user.branch || "").toUpperCase());
      if (!allowed) {
        return json({ success: false, error: "NOT_AUTHORIZED" }, 403);
      }
    }

    // BAGO: magpapadala lang kung may approve/decline na naitala sa audit sa nakaraang 15 minuto
    // (para hindi magamit ang function sa pagpapadala ng email kahit kailan)
    const fifteenMinutesAgo = new Date(Date.now() - 15 * 60 * 1000).toISOString();
    const { data: recentDecision } = await supabaseAdmin
      .from("account_audit_trail")
      .select("id")
      .eq("username_affected", user.username)
      .in("action", ["APPROVED", "REJECTED"])
      .gte("performed_at", fifteenMinutesAgo)
      .limit(1);

    if (!recentDecision || recentDecision.length === 0) {
      return json({ success: false, error: "No recent decision for this account." }, 400);
    }

    let subject, body;

    if (user.status === "APPROVED") {
      subject = "Your GAMOT Account Has Been Approved";
      body = `Hi ${user.username},\n\nGreat news! Your account for ${user.facility} has been APPROVED.\n\n` +
             `You may now log in using:\n\nUsername: ${user.username}\n` +
             `Password: the password you created during registration\n\n` +
             `If you forgot your password, you can use the "Forgot Password?" link on the login page to reset it.\n\n` +
             `Thank you,\nEasy GAMOT Online Support Team`;
    } else if (user.status === "REJECTED") {
      subject = "Your GAMOT Account Registration Was Declined";
      body = `Hi ${user.username},\n\nWe regret to inform you that your account registration for ${user.facility} was DECLINED.\n\n` +
             `Reason: ${user.decline_reason || "No reason provided."}\n\n` +
             `Please correct the issue and register again, or contact support.\n\nThank you,\nEasy GAMOT Online Support Team`;
    } else {
      return json({ success: false, error: "Account has no approval decision yet." }, 400);
    }

    const sendResult = await sendEmailWithFallback(user.email, subject, body);

    return json({ success: sendResult.success, method: sendResult.method, error: sendResult.error });
  } catch (e) {
    return json({ success: false, error: e.message }, 500);
  }
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
