import { createClient } from "https://esm.sh/@supabase/supabase-js@2";

const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type",
};

Deno.serve(async (req) => {
  if (req.method === "OPTIONS") {
    return new Response("ok", { headers: corsHeaders });
  }

  try {
    const { email } = await req.json();

    if (!email || !email.includes("@")) {
      return new Response(JSON.stringify({ success: false, error: "Please provide a valid email address." }), {
        status: 400,
        headers: { ...corsHeaders, "Content-Type": "application/json" }
      });
    }

    const SUPABASE_SECRET_KEYS = JSON.parse(Deno.env.get("SUPABASE_SECRET_KEYS")!);
    const supabaseAdmin = createClient(
      Deno.env.get("SUPABASE_URL")!,
      SUPABASE_SECRET_KEYS["default"]
    );

    // Rate limiting: max 5 requests kada email kada araw, 1 minuto cooldown sa pagitan
    const oneMinuteAgo = new Date(Date.now() - 60 * 1000).toISOString();
    const { data: recent } = await supabaseAdmin
      .from("registration_email_verifications")
      .select("id")
      .ilike("email", email)
      .gte("created_at", oneMinuteAgo);

    if (recent && recent.length > 0) {
      return new Response(JSON.stringify({ success: false, error: "Please wait a minute before requesting another code." }), {
        status: 429,
        headers: { ...corsHeaders, "Content-Type": "application/json" }
      });
    }

    const oneDayAgo = new Date(Date.now() - 24 * 60 * 60 * 1000).toISOString();
    const { data: daily } = await supabaseAdmin
      .from("registration_email_verifications")
      .select("id")
      .ilike("email", email)
      .gte("created_at", oneDayAgo);

    if (daily && daily.length >= 5) {
      return new Response(JSON.stringify({ success: false, error: "Too many verification requests for this email today." }), {
        status: 429,
        headers: { ...corsHeaders, "Content-Type": "application/json" }
      });
    }

    // BAGO: cryptographically secure na random (dati Math.random)
    const otp = (100000 + (crypto.getRandomValues(new Uint32Array(1))[0] % 900000)).toString();
    const expiresAt = new Date(Date.now() + 15 * 60 * 1000).toISOString();

    await supabaseAdmin.from("registration_email_verifications").insert({
      email: email,
      otp: otp,
      expires_at: expiresAt
    });

    const subject = "Verify Your Email — GAMOT Registration";
    const body = `Hi,\n\nYour email verification code for GAMOT registration is: ${otp}\n\n` +
                 `This code will expire in 15 minutes. If you did not request this, please ignore this email.\n\n` +
                 `Thank you,\nEasy GAMOT Online Support Team`;

    const sendResult = await sendEmailWithFallback(email, subject, body);

    return new Response(JSON.stringify({ success: sendResult.success, error: sendResult.error }), {
      headers: { ...corsHeaders, "Content-Type": "application/json" }
    });
  } catch (e) {
    return new Response(JSON.stringify({ success: false, error: e.message }), {
      status: 500,
      headers: { ...corsHeaders, "Content-Type": "application/json" }
    });
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
