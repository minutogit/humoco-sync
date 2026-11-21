use std::fmt::Write as _;
use std::net::SocketAddr;

use axum::extract::{ConnectInfo, Query, State};
use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::response::{Html, IntoResponse, Redirect, Response};
use axum::routing::{get, post};
use axum::{Form, Router};
use serde::Deserialize;

use crate::config::Config;
use crate::crypto::{
    canonicalize_email, constant_time_eq_str, create_pow_challenge, generate_session_csrf_pair,
    hmac_email, normalize_pubkey_hex, random_hex, sha256_hex, sign_stateless_token, unix_now,
    verify_pow_solution, verify_stateless_token, SignedActionToken,
};
use crate::db::AccountStatus;
use crate::ratelimit::extract_client_ip;
use crate::state::AppState;

const ADMIN_SESSION_COOKIE: &str = "humoco_admin_sess";

pub fn web_router(cfg: &Config) -> Router<AppState> {
    let mut router = Router::new().route("/", get(landing_page));
    if !cfg.mode.enable_builtin_ui {
        return router;
    }

    let reg = cfg.mode.register_path.clone();
    router = router
        .route(&reg, get(register_page))
        .route(&format!("{}/email", reg), post(register_email_submit))
        .route(&format!("{}/confirm", reg), get(register_confirm))
        .route(&format!("{}/redeem", reg), post(register_redeem_submit))
        .route(&format!("{}/pow", reg), post(register_pow_submit))
        .route(&format!("{}/open", reg), post(register_open_submit))
        .route(
            &format!("{}/delete-request", reg),
            post(register_delete_request),
        )
        .route(
            &format!("{}/delete-confirm", reg),
            get(register_delete_confirm),
        )
        .route("/admin", get(admin_dashboard))
        .route("/admin/login", post(admin_login_submit))
        .route("/admin/logout", post(admin_logout_submit))
        .route("/admin/users/profile", post(admin_user_profile_submit))
        .route("/admin/users/status", post(admin_user_status_submit))
        .route("/admin/users/delete", post(admin_user_delete_submit))
        .route("/admin/codes", post(admin_create_code_submit));

    router
}

fn html_response(status: StatusCode, body: String) -> Response {
    let mut resp = (status, Html(body)).into_response();
    let h = resp.headers_mut();
    h.insert(
        header::HeaderName::from_static("content-security-policy"),
        HeaderValue::from_static(
            "default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; form-action 'self'",
        ),
    );
    h.insert(
        header::HeaderName::from_static("x-frame-options"),
        HeaderValue::from_static("DENY"),
    );
    h.insert(
        header::HeaderName::from_static("x-content-type-options"),
        HeaderValue::from_static("nosniff"),
    );
    h.insert(
        header::HeaderName::from_static("referrer-policy"),
        HeaderValue::from_static("no-referrer"),
    );
    h.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    resp
}

fn escape_html(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len());
    for ch in raw.chars() {
        match ch {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            c => out.push(c),
        }
    }
    out
}

fn format_bytes(bytes: u64) -> String {
    if bytes >= 1024 * 1024 {
        format!("{:.2} MiB", bytes as f64 / (1024.0 * 1024.0))
    } else if bytes >= 1024 {
        format!("{:.1} KiB", bytes as f64 / 1024.0)
    } else {
        format!("{} B", bytes)
    }
}

fn layout_html(title: &str, service_name: &str, operator_contact: &str, body: &str) -> String {
    let contact_html = if operator_contact.trim().is_empty() {
        String::new()
    } else {
        format!(
            " | Contact: <code>{}</code>",
            escape_html(operator_contact.trim())
        )
    };
    format!(
        r#"<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{title} — {svc}</title>
<style>
  :root {{ --bg:#0f172a; --card:#1e293b; --muted:#94a3b8; --text:#f8fafc; --acc:#38bdf8; --ok:#22c55e; --warn:#f59e0b; --err:#ef4444; --border:#334155; }}
  * {{ box-sizing:border-box; }}
  body {{ margin:0; font-family:system-ui,-apple-system,sans-serif; background:var(--bg); color:var(--text); line-height:1.5; }}
  .wrap {{ max-width:860px; margin:2rem auto; padding:0 1rem; }}
  .card {{ background:var(--card); border:1px solid var(--border); border-radius:12px; padding:1.25rem; margin-bottom:1rem; }}
  h1,h2,h3 {{ margin-top:0; }}
  h1 {{ font-size:1.45rem; margin-bottom:.4rem; }}
  h2 {{ font-size:1.1rem; color:var(--acc); }}
  label {{ display:block; font-size:.875rem; color:var(--muted); margin-top:.75rem; margin-bottom:.25rem; }}
  input, select {{ width:100%; padding:.6rem .75rem; background:#0b1220; border:1px solid var(--border); border-radius:8px; color:var(--text); font-size:.95rem; }}
  input[readonly] {{ opacity:.85; }}
  .row {{ display:grid; grid-template-columns:1fr 1fr; gap:1rem; }}
  @media(max-width:680px){{ .row{{ grid-template-columns:1fr; }} }}
  button,.btn {{ display:inline-block; margin-top:.85rem; padding:.6rem 1rem; background:var(--acc); color:#062033; font-weight:600; border:0; border-radius:8px; cursor:pointer; text-decoration:none; font-size:.92rem; }}
  button.danger {{ background:var(--err); color:#fff; }}
  button.secondary {{ background:#334155; color:var(--text); }}
  .badge {{ display:inline-block; padding:.2rem .55rem; border-radius:999px; font-size:.8rem; font-weight:600; }}
  .badge.ok {{ background:#14532d; color:#86efac; }}
  .badge.warn {{ background:#451a03; color:#fcd34d; }}
  .badge.err {{ background:#450a0a; color:#fca5a5; }}
  .alert {{ padding:.75rem 1rem; border-radius:8px; margin-bottom:1rem; border:1px solid var(--border); }}
  .alert.ok {{ background:#052e16; border-color:#166534; }}
  .alert.err {{ background:#450a0a; border-color:#991b1b; }}
  .alert.warn {{ background:#451a03; border-color:#b45309; }}
  table {{ width:100%; border-collapse:collapse; font-size:.85rem; }}
  th,td {{ padding:.45rem .5rem; border-bottom:1px solid var(--border); text-align:left; }}
  code {{ background:#0b1220; padding:.1rem .35rem; border-radius:4px; font-size:.85em; word-break:break-all; }}
  .muted {{ color:var(--muted); font-size:.875rem; }}
  .footer {{ margin-top:2rem; color:var(--muted); font-size:.8rem; text-align:center; }}
</style>
</head>
<body>
<div class="wrap">
  <h1>{svc}</h1>
  {body}
  <div class="footer">HuMoCo Sync Service &mdash; Encrypted Zero-Knowledge Relay{contact_html}</div>
</div>
</body>
</html>"#,
        title = escape_html(title),
        svc = escape_html(service_name),
        body = body,
        contact_html = contact_html
    )
}

async fn landing_page(State(state): State<AppState>) -> Response {
    let mut body = String::from(
        r#"<div class="card"><h2>Endpoint Ready</h2><p class="muted">Configure your Human Money App with this server URL to synchronize end-to-end encrypted data.</p>"#,
    );
    if let Some(reg_url) = state.config.register_url() {
        if state.config.mode.enable_builtin_ui {
            let _ = write!(
                body,
                r#"<p><a class="btn" href="{}">Open Public Registration / Account Portal</a></p>"#,
                escape_html(&state.config.mode.register_path)
            );
        } else {
            let _ = write!(
                body,
                r#"<p class="muted">Registration portal: <code>{}</code></p>"#,
                escape_html(&reg_url)
            );
        }
    }
    let _ = write!(
        body,
        r#"<p class="muted">Sync endpoint: <code>/sync.php</code> &amp; <code>/sync</code></p></div>"#
    );
    html_response(
        StatusCode::OK,
        layout_html(
            "Home",
            &state.config.mode.service_name,
            &state.config.mode.operator_contact,
            &body,
        ),
    )
}

#[derive(Deserialize)]
struct RegisterQuery {
    #[serde(default)]
    key: String,
    #[serde(default)]
    msg: Option<String>,
    #[serde(default)]
    err: Option<String>,
}

async fn register_page(State(state): State<AppState>, Query(q): Query<RegisterQuery>) -> Response {
    if !state.config.mode.enable_public_registration {
        let html = layout_html(
            "Registration Disabled",
            &state.config.mode.service_name,
            &state.config.mode.operator_contact,
            r#"<div class="card"><span class="badge warn">Private Host</span><p class="muted" style="margin-top:.75rem;">Public self-registration is disabled on this server.</p></div>"#,
        );
        return html_response(StatusCode::FORBIDDEN, html);
    }

    let reg_base = state.config.mode.register_path.clone();
    let now = unix_now();
    let clean_key = normalize_pubkey_hex(&q.key);
    let key_input_val = clean_key.as_deref().unwrap_or(q.key.trim());

    let mut body = String::new();
    if let Some(ref m) = q.msg {
        let _ = write!(body, r#"<div class="alert ok">{}</div>"#, escape_html(m));
    }
    if let Some(ref e) = q.err {
        let _ = write!(body, r#"<div class="alert err">{}</div>"#, escape_html(e));
    }
    if !q.key.trim().is_empty() && clean_key.is_none() {
        body.push_str(
            r#"<div class="alert err">Invalid Sync Key format: expected 64 lowercase hexadecimal characters.</div>"#,
        );
    }

    // Key Status Card
    let _ = write!(
        body,
        r#"<div class="card"><h2>1. Your Public Sync Key</h2>
        <form method="GET" action="{reg_base}">
          <label for="key">Public Registration Key (64 hex chars)</label>
          <input id="key" name="key" value="{key_val}" placeholder="64-hex key from Human Money App" required>
          <button type="submit" class="secondary">Check Status</button>
        </form>"#,
        reg_base = escape_html(&reg_base),
        key_val = escape_html(key_input_val)
    );

    if let Some(ref pk) = clean_key {
        let access = state
            .db
            .resolve_member_access(&state.config, pk, now)
            .ok()
            .flatten();
        let reg_rec = state.db.get_registered_user(pk).ok().flatten();
        if let Some(ref eff) = access {
            let badge = if eff.in_grace_period {
                r#"<span class="badge warn">Grace Period (Expiring Soon)</span>"#
            } else {
                r#"<span class="badge ok">Active</span>"#
            };
            let _ = write!(
                body,
                r#"<div style="margin-top:1rem;">{badge}
                <p>Profile: <strong>{}</strong> (Total quota: {})</p>"#,
                escape_html(&eff.profile.display_name),
                format_bytes(eff.profile.max_total_bytes)
            );
            if let Some(v) = eff.valid_until {
                let _ = write!(
                    body,
                    r#"<p class="muted">Valid until UNIX timestamp: <code>{}</code></p>"#,
                    v
                );
            }
            if eff.in_grace_period {
                let _ = write!(
                    body,
                    r#"<div class="alert warn">Subscription expired &mdash; you are in the {} day grace window before automatic downgrade to the free profile.</div>"#,
                    state.config.storage.downgrade_grace_days
                );
            }
            body.push_str(
                r#"<p class="muted">You can now return to your Human Money App and click <strong>Re-check Activation</strong>.</p></div>"#,
            );
        } else if reg_rec
            .as_ref()
            .is_some_and(|r| r.status == AccountStatus::Suspended)
        {
            body.push_str(r#"<div style="margin-top:1rem;"><span class="badge err">Suspended</span><p class="muted">This account has been suspended by the operator.</p></div>"#);
        } else {
            body.push_str(r#"<div style="margin-top:1rem;"><span class="badge warn">Not Activated Yet</span><p class="muted">Complete one of the activation methods below.</p></div>"#);
        }
    }
    body.push_str("</div>");

    let key_for_forms = clean_key.as_deref().unwrap_or("");
    let esc_key = escape_html(key_for_forms);

    // Email Double-Opt-In Card
    if state.config.gate_enabled("email") {
        let store_contact = state
            .config
            .profiles
            .get(&state.config.mode.default_public_profile)
            .is_some_and(|p| p.store_contact_email);
        let pii_note = if store_contact {
            "Email is stored encrypted for account management."
        } else {
            "Zero-PII GDPR Privacy: your email address is NOT saved on disk. Only a keyed HMAC-SHA256 hash is kept to prevent duplicate free registrations and verify self-deletion."
        };
        let _ = write!(
            body,
            r#"<div class="card">
            <h2>Activate Free Tier via Email Verification</h2>
            <p class="muted">{pii_note}</p>
            <form method="POST" action="{reg_base}/email">
              <label>Public Sync Key (64 hex)</label>
              <input name="pubkey" value="{esc_key}" placeholder="64-hex pubkey" required>
              <label>Email Address</label>
              <input type="email" name="email" placeholder="you@example.org" required>
              <button type="submit">Send Confirmation Link</button>
            </form></div>"#,
            pii_note = pii_note,
            reg_base = escape_html(&reg_base),
            esc_key = esc_key
        );
    }

    // Redeem Code Card (Invite or Paid Upgrade)
    if state.config.gate_enabled("code") {
        let _ = write!(
            body,
            r#"<div class="card">
            <h2>Activate or Upgrade with Redeem Code</h2>
            <p class="muted">Enter an Invite Code or Supporter Pro Upgrade Code.</p>
            <form method="POST" action="{reg_base}/redeem">
              <label>Public Sync Key (64 hex)</label>
              <input name="pubkey" value="{esc_key}" placeholder="64-hex pubkey" required>
              <label>Redeem Code</label>
              <input name="code" placeholder="PRO-XXXXXX-XXXXXX" required>
              <button type="submit">Redeem Code</button>
            </form></div>"#,
            reg_base = escape_html(&reg_base),
            esc_key = esc_key
        );
    }

    // PoW Gate Card
    if state.config.gate_enabled("pow") && !key_for_forms.is_empty() {
        let difficulty = state.config.security.pow_difficulty_bits;
        let challenge = create_pow_challenge(state.db.pepper(), key_for_forms, difficulty, now);
        let _ = write!(
            body,
            r#"<div class="card">
            <h2>Activate via Browser Proof-of-Work ({difficulty} bits)</h2>
            <p class="muted">Spam protection without sharing an email address.</p>
            <form id="powForm" method="POST" action="{reg_base}/pow">
              <input type="hidden" name="pubkey" value="{esc_key}">
              <input type="hidden" name="challenge" id="powChallenge" value="{challenge}">
              <label>PoW Nonce</label>
              <input name="nonce" id="powNonce" placeholder="Click Solve automatically or enter nonce" required>
              <button type="button" id="powSolveBtn" class="secondary">Solve in Browser</button>
              <button type="submit">Verify &amp; Activate</button>
              <span id="powStatus" class="muted" style="margin-left:.75rem;"></span>
            </form>
            <script>
            (function(){{
              var btn=document.getElementById('powSolveBtn');
              if(!btn||!window.crypto||!window.crypto.subtle)return;
              var diff={difficulty};
              var chal=document.getElementById('powChallenge').value;
              var status=document.getElementById('powStatus');
              function okZero(buf,bits){{
                var bytes=new Uint8Array(buf),need=bits;
                for(var i=0;i<bytes.length&&need>0;i++){{
                  if(need>=8){{if(bytes[i]!==0)return false;need-=8;}}
                  else{{var mask=0xff<<(8-need);if((bytes[i]&mask)!==0)return false;need=0;}}
                }}
                return true;
              }}
              btn.addEventListener('click',async function(){{
                btn.disabled=true;status.textContent='Solving...';
                var enc=new TextEncoder();
                for(var n=0;;n++){{
                  var data=enc.encode(chal+':'+n);
                  var hash=await crypto.subtle.digest('SHA-256',data);
                  if(okZero(hash,diff)){{
                    document.getElementById('powNonce').value=String(n);
                    status.textContent='Solved (nonce='+n+'). Click Verify & Activate.';
                    btn.disabled=false;
                    return;
                  }}
                  if(n%500===0)status.textContent='Solving... '+n;
                }}
              }});
            }})();
            </script></div>"#,
            difficulty = difficulty,
            reg_base = escape_html(&reg_base),
            esc_key = esc_key,
            challenge = escape_html(&challenge)
        );
    }

    // Open Registration Card
    if state.config.gate_enabled("open") {
        let _ = write!(
            body,
            r#"<div class="card">
            <h2>Instant Activation (Open Registration)</h2>
            <p class="muted">Subject to daily subnet rate limits.</p>
            <form method="POST" action="{reg_base}/open">
              <label>Public Sync Key (64 hex)</label>
              <input name="pubkey" value="{esc_key}" placeholder="64-hex pubkey" required>
              <button type="submit">Activate Key Now</button>
            </form></div>"#,
            reg_base = escape_html(&reg_base),
            esc_key = esc_key
        );
    }

    // Verified Self-Deletion Card (GDPR Art. 17)
    let _ = write!(
        body,
        r#"<div class="card">
        <h2>Delete Account &amp; Encrypted Blobs (GDPR Self-Deletion)</h2>
        <p class="muted">Unauthenticated deletion by public key alone is forbidden. If you registered via email, confirm your email below to receive a single-use deletion link. Otherwise, delete directly inside the Human Money App via cryptographic signature (<code>DELETE ?account</code>).</p>
        <form method="POST" action="{reg_base}/delete-request">
          <label>Public Sync Key (64 hex)</label>
          <input name="pubkey" value="{esc_key}" placeholder="64-hex pubkey" required>
          <label>Email Used During Registration</label>
          <input type="email" name="email" placeholder="you@example.org" required>
          <button type="submit" class="danger">Request Deletion Link</button>
        </form></div>"#,
        reg_base = escape_html(&reg_base),
        esc_key = esc_key
    );

    html_response(
        StatusCode::OK,
        layout_html(
            "Registration",
            &state.config.mode.service_name,
            &state.config.mode.operator_contact,
            &body,
        ),
    )
}

#[derive(Deserialize)]
struct EmailRegisterForm {
    pubkey: String,
    email: String,
}

async fn register_email_submit(
    State(state): State<AppState>,
    peer: Option<ConnectInfo<SocketAddr>>,
    headers: HeaderMap,
    Form(form): Form<EmailRegisterForm>,
) -> Response {
    if !state.config.gate_enabled("email") {
        return Redirect::to(&format!(
            "{}?err=Email+registration+disabled",
            state.config.mode.register_path
        ))
        .into_response();
    }
    let ip = extract_client_ip(
        peer.map(|ConnectInfo(s)| s),
        &headers,
        state.config.server.trusted_proxy_hops,
    );
    if !state.rate_limiter.allow_ip(ip) {
        return Redirect::to(&format!(
            "{}?err=Rate+limit+exceeded",
            state.config.mode.register_path
        ))
        .into_response();
    }
    let Some(pubkey) = normalize_pubkey_hex(&form.pubkey) else {
        return Redirect::to(&format!(
            "{}?err=Invalid+public+sync+key",
            state.config.mode.register_path
        ))
        .into_response();
    };
    let Some(canon_email) = canonicalize_email(&form.email) else {
        return Redirect::to(&format!(
            "{}?key={}&err=Invalid+email+address",
            state.config.mode.register_path, pubkey
        ))
        .into_response();
    };
    if let Some(resp) = ensure_pubkey_unregistered_for_public_gate(&state, &pubkey) {
        return resp;
    }
    if let Err(err) = state
        .db
        .check_email_not_used_by_other(&canon_email, &pubkey)
    {
        return Redirect::to(&format!(
            "{}?key={}&err={}",
            state.config.mode.register_path,
            pubkey,
            url_encode(&err.to_string())
        ))
        .into_response();
    }
    if !state.rate_limiter.check_and_record_registration_subnet(ip) {
        return Redirect::to(&format!(
            "{}?key={}&err=Daily+subnet+registration+limit+reached",
            state.config.mode.register_path, pubkey
        ))
        .into_response();
    }

    let now = unix_now();
    let email_hmac = hmac_email(state.db.pepper(), &canon_email);
    let profile_name = state.config.mode.default_public_profile.clone();
    let store_contact = state
        .config
        .profiles
        .get(&profile_name)
        .is_some_and(|p| p.store_contact_email);

    let claims = SignedActionToken {
        action: "confirm_register".to_string(),
        pubkey: pubkey.clone(),
        email_hmac,
        contact_email: if store_contact {
            Some(canon_email.clone())
        } else {
            None
        },
        profile: profile_name,
        exp: now.saturating_add((state.config.email.token_ttl_minutes as u64).max(5) * 60),
        jti: random_hex(16),
    };
    let token = sign_stateless_token(state.db.pepper(), &claims);
    let confirm_link = format!(
        "{}{}/confirm?token={}",
        state.config.server.public_base_url, state.config.mode.register_path, token
    );
    let mail_body = format!(
        "Hello,\n\nPlease confirm your HuMoCo Sync registration for public sync key:\n{}\n\nClick here to activate:\n{}\n\nThis link expires in {} minutes.\n",
        pubkey, confirm_link, state.config.email.token_ttl_minutes
    );
    if let Err(err) = state
        .mailer
        .send_mail(
            form.email.trim(),
            &format!(
                "{} — Confirm Sync Key Activation",
                state.config.mode.service_name
            ),
            &mail_body,
        )
        .await
    {
        return Redirect::to(&format!(
            "{}?key={}&err={}",
            state.config.mode.register_path,
            pubkey,
            url_encode(&format!("Failed to send confirmation email: {}", err))
        ))
        .into_response();
    }

    Redirect::to(&format!(
        "{}?key={}&msg={}",
        state.config.mode.register_path,
        pubkey,
        url_encode(
            "Confirmation link dispatched. Check your inbox and click the link to activate."
        )
    ))
    .into_response()
}

#[derive(Deserialize)]
struct TokenQuery {
    #[serde(default)]
    token: String,
}

async fn register_confirm(
    State(state): State<AppState>,
    peer: Option<ConnectInfo<SocketAddr>>,
    headers: HeaderMap,
    Query(q): Query<TokenQuery>,
) -> Response {
    if !state.config.mode.enable_public_registration {
        return Redirect::to("/").into_response();
    }
    if !state.config.gate_enabled("email") {
        return Redirect::to(&format!(
            "{}?err=Email+registration+disabled",
            state.config.mode.register_path
        ))
        .into_response();
    }
    let ip = extract_client_ip(
        peer.map(|ConnectInfo(s)| s),
        &headers,
        state.config.server.trusted_proxy_hops,
    );
    if !state.rate_limiter.allow_ip(ip) {
        return html_response(
            StatusCode::TOO_MANY_REQUESTS,
            layout_html(
                "Rate Limit Exceeded",
                &state.config.mode.service_name,
                &state.config.mode.operator_contact,
                r#"<div class="alert err">Too many requests. Please try again shortly.</div>"#,
            ),
        );
    }
    let now = unix_now();
    let claims = match verify_stateless_token(state.db.pepper(), &q.token, "confirm_register", now)
    {
        Ok(c) => c,
        Err(e) => {
            return Redirect::to(&format!(
                "{}?err={}",
                state.config.mode.register_path,
                url_encode(&e)
            ))
            .into_response();
        }
    };
    let Some(pubkey) = normalize_pubkey_hex(&claims.pubkey) else {
        return Redirect::to(&format!(
            "{}?err=Invalid+public+sync+key",
            state.config.mode.register_path
        ))
        .into_response();
    };
    match state.db.consume_action_jti(&claims.jti, claims.exp, now) {
        Ok(true) => {}
        _ => {
            return Redirect::to(&format!(
                "{}?key={}&err=Confirmation+link+already+used",
                state.config.mode.register_path, pubkey
            ))
            .into_response();
        }
    }

    // Bind email_hmac directly even if store_contact_email = false
    let res = state.db.register_or_upgrade_user_by_hmac(
        &state.config,
        &pubkey,
        &claims.profile,
        Some(&claims.email_hmac),
        claims.contact_email.as_deref(),
        None,
        "email",
        now,
    );
    match res {
        Ok(_) => Redirect::to(&format!(
            "{}?key={}&msg={}",
            state.config.mode.register_path,
            pubkey,
            url_encode("Key activated! You can return to the Human Money App and click Re-check Activation.")
        ))
        .into_response(),
        Err(e) => Redirect::to(&format!(
            "{}?key={}&err={}",
            state.config.mode.register_path,
            pubkey,
            url_encode(&e.to_string())
        ))
        .into_response(),
    }
}

#[derive(Deserialize)]
struct RedeemForm {
    pubkey: String,
    code: String,
}

async fn register_redeem_submit(
    State(state): State<AppState>,
    peer: Option<ConnectInfo<SocketAddr>>,
    headers: HeaderMap,
    Form(form): Form<RedeemForm>,
) -> Response {
    if !state.config.gate_enabled("code") {
        return Redirect::to(&format!(
            "{}?err=Code+redemption+disabled",
            state.config.mode.register_path
        ))
        .into_response();
    }
    let ip = extract_client_ip(
        peer.map(|ConnectInfo(s)| s),
        &headers,
        state.config.server.trusted_proxy_hops,
    );
    if !state.rate_limiter.allow_ip(ip) {
        return Redirect::to(&format!(
            "{}?err=Rate+limit+exceeded",
            state.config.mode.register_path
        ))
        .into_response();
    }
    let Some(pubkey) = normalize_pubkey_hex(&form.pubkey) else {
        return Redirect::to(&format!(
            "{}?err=Invalid+public+sync+key",
            state.config.mode.register_path
        ))
        .into_response();
    };
    let now = unix_now();
    match state
        .db
        .redeem_code_for_pubkey(&state.config, &pubkey, &form.code, now)
    {
        Ok(rec) => Redirect::to(&format!(
            "{}?key={}&msg={}",
            state.config.mode.register_path,
            pubkey,
            url_encode(&format!("Code redeemed! Profile active: {}", rec.profile))
        ))
        .into_response(),
        Err(e) => Redirect::to(&format!(
            "{}?key={}&err={}",
            state.config.mode.register_path,
            pubkey,
            url_encode(&e.to_string())
        ))
        .into_response(),
    }
}

#[derive(Deserialize)]
struct PowForm {
    pubkey: String,
    challenge: String,
    nonce: String,
}

async fn register_pow_submit(
    State(state): State<AppState>,
    peer: Option<ConnectInfo<SocketAddr>>,
    headers: HeaderMap,
    Form(form): Form<PowForm>,
) -> Response {
    if !state.config.gate_enabled("pow") {
        return Redirect::to(&format!(
            "{}?err=PoW+registration+disabled",
            state.config.mode.register_path
        ))
        .into_response();
    }
    let ip = extract_client_ip(
        peer.map(|ConnectInfo(s)| s),
        &headers,
        state.config.server.trusted_proxy_hops,
    );
    if !state.rate_limiter.allow_ip(ip) {
        return Redirect::to(&format!(
            "{}?err=Rate+limit+exceeded",
            state.config.mode.register_path
        ))
        .into_response();
    }
    let Some(pubkey) = normalize_pubkey_hex(&form.pubkey) else {
        return Redirect::to(&format!(
            "{}?err=Invalid+public+sync+key",
            state.config.mode.register_path
        ))
        .into_response();
    };
    if let Some(resp) = ensure_pubkey_unregistered_for_public_gate(&state, &pubkey) {
        return resp;
    }
    let now = unix_now();
    if let Err(err) = verify_pow_solution(
        state.db.pepper(),
        &form.challenge,
        &pubkey,
        &form.nonce,
        now,
    ) {
        return Redirect::to(&format!(
            "{}?key={}&err={}",
            state.config.mode.register_path,
            pubkey,
            url_encode(&err)
        ))
        .into_response();
    }
    let pow_exp = form
        .challenge
        .trim()
        .split('.')
        .nth(2)
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or_else(|| now.saturating_add(300));
    let pow_jti = format!("pow:{}", sha256_hex(form.challenge.trim().as_bytes()));
    match state.db.consume_action_jti(&pow_jti, pow_exp, now) {
        Ok(true) => {}
        _ => {
            return Redirect::to(&format!(
                "{}?key={}&err=PoW+challenge+already+used",
                state.config.mode.register_path, pubkey
            ))
            .into_response();
        }
    }
    if !state.rate_limiter.check_and_record_registration_subnet(ip) {
        return Redirect::to(&format!(
            "{}?key={}&err=Daily+subnet+registration+limit+reached",
            state.config.mode.register_path, pubkey
        ))
        .into_response();
    }

    let prof = state.config.mode.default_public_profile.clone();
    match state
        .db
        .register_or_upgrade_user(&state.config, &pubkey, &prof, None, None, "pow", now)
    {
        Ok(_) => Redirect::to(&format!(
            "{}?key={}&msg=Activated+via+Proof-of-Work!",
            state.config.mode.register_path, pubkey
        ))
        .into_response(),
        Err(e) => Redirect::to(&format!(
            "{}?key={}&err={}",
            state.config.mode.register_path,
            pubkey,
            url_encode(&e.to_string())
        ))
        .into_response(),
    }
}

#[derive(Deserialize)]
struct OpenForm {
    pubkey: String,
}

async fn register_open_submit(
    State(state): State<AppState>,
    peer: Option<ConnectInfo<SocketAddr>>,
    headers: HeaderMap,
    Form(form): Form<OpenForm>,
) -> Response {
    if !state.config.gate_enabled("open") {
        return Redirect::to(&format!(
            "{}?err=Open+registration+disabled",
            state.config.mode.register_path
        ))
        .into_response();
    }
    let ip = extract_client_ip(
        peer.map(|ConnectInfo(s)| s),
        &headers,
        state.config.server.trusted_proxy_hops,
    );
    if !state.rate_limiter.allow_ip(ip) {
        return Redirect::to(&format!(
            "{}?err=Rate+limit+exceeded",
            state.config.mode.register_path
        ))
        .into_response();
    }
    let Some(pubkey) = normalize_pubkey_hex(&form.pubkey) else {
        return Redirect::to(&format!(
            "{}?err=Invalid+public+sync+key",
            state.config.mode.register_path
        ))
        .into_response();
    };
    if let Some(resp) = ensure_pubkey_unregistered_for_public_gate(&state, &pubkey) {
        return resp;
    }
    if !state.rate_limiter.check_and_record_registration_subnet(ip) {
        return Redirect::to(&format!(
            "{}?key={}&err=Daily+subnet+registration+limit+reached",
            state.config.mode.register_path, pubkey
        ))
        .into_response();
    }
    let now = unix_now();
    let prof = state.config.mode.default_public_profile.clone();
    match state
        .db
        .register_or_upgrade_user(&state.config, &pubkey, &prof, None, None, "open", now)
    {
        Ok(_) => Redirect::to(&format!(
            "{}?key={}&msg=Account+activated!",
            state.config.mode.register_path, pubkey
        ))
        .into_response(),
        Err(e) => Redirect::to(&format!(
            "{}?key={}&err={}",
            state.config.mode.register_path,
            pubkey,
            url_encode(&e.to_string())
        ))
        .into_response(),
    }
}

#[derive(Deserialize)]
struct DeleteRequestForm {
    pubkey: String,
    email: String,
}

async fn register_delete_request(
    State(state): State<AppState>,
    peer: Option<ConnectInfo<SocketAddr>>,
    headers: HeaderMap,
    Form(form): Form<DeleteRequestForm>,
) -> Response {
    let ip = extract_client_ip(
        peer.map(|ConnectInfo(s)| s),
        &headers,
        state.config.server.trusted_proxy_hops,
    );
    if !state.rate_limiter.allow_ip(ip) {
        return Redirect::to(&format!(
            "{}?err=Rate+limit+exceeded",
            state.config.mode.register_path
        ))
        .into_response();
    }
    let Some(pubkey) = normalize_pubkey_hex(&form.pubkey) else {
        return Redirect::to(&format!(
            "{}?err=Invalid+public+sync+key",
            state.config.mode.register_path
        ))
        .into_response();
    };
    let Some(canon_email) = canonicalize_email(&form.email) else {
        return Redirect::to(&format!(
            "{}?key={}&err=Invalid+email+address",
            state.config.mode.register_path, pubkey
        ))
        .into_response();
    };

    let candidate_hmac = hmac_email(state.db.pepper(), &canon_email);
    if let Ok(Some(rec)) = state.db.get_registered_user(&pubkey) {
        if rec.email_hmac.as_deref() == Some(candidate_hmac.as_str()) {
            let now = unix_now();
            let claims = SignedActionToken {
                action: "delete_account".to_string(),
                pubkey: pubkey.clone(),
                email_hmac: candidate_hmac,
                contact_email: None,
                profile: rec.profile,
                exp: now.saturating_add(30 * 60),
                jti: random_hex(16),
            };
            let token = sign_stateless_token(state.db.pepper(), &claims);
            let del_link = format!(
                "{}{}/delete-confirm?token={}",
                state.config.server.public_base_url, state.config.mode.register_path, token
            );
            let mail_body = format!(
                "Hello,\n\nSomeone requested permanent deletion of your HuMoCo Sync account and encrypted blobs for key:\n{}\n\nClick to permanently delete:\n{}\n\nIf you did not request this, ignore this email.\n",
                pubkey, del_link
            );
            let _ = state
                .mailer
                .send_mail(
                    form.email.trim(),
                    &format!(
                        "{} — Confirm Account Deletion",
                        state.config.mode.service_name
                    ),
                    &mail_body,
                )
                .await;
        }
    }

    // Generic message prevents probing whether arbitrary key is bound to an email
    Redirect::to(&format!(
        "{}?key={}&msg={}",
        state.config.mode.register_path,
        pubkey,
        url_encode("If the key and email match an email-verified account, a deletion confirmation link has been sent.")
    ))
    .into_response()
}

async fn register_delete_confirm(
    State(state): State<AppState>,
    peer: Option<ConnectInfo<SocketAddr>>,
    headers: HeaderMap,
    Query(q): Query<TokenQuery>,
) -> Response {
    let ip = extract_client_ip(
        peer.map(|ConnectInfo(s)| s),
        &headers,
        state.config.server.trusted_proxy_hops,
    );
    if !state.rate_limiter.allow_ip(ip) {
        return html_response(
            StatusCode::TOO_MANY_REQUESTS,
            layout_html(
                "Rate Limit Exceeded",
                &state.config.mode.service_name,
                &state.config.mode.operator_contact,
                r#"<div class="alert err">Too many requests. Please try again shortly.</div>"#,
            ),
        );
    }
    let now = unix_now();
    let claims = match verify_stateless_token(state.db.pepper(), &q.token, "delete_account", now) {
        Ok(c) => c,
        Err(e) => {
            return Redirect::to(&format!(
                "{}?err={}",
                state.config.mode.register_path,
                url_encode(&e)
            ))
            .into_response();
        }
    };
    let Some(pubkey) = normalize_pubkey_hex(&claims.pubkey) else {
        return Redirect::to(&format!(
            "{}?err=Invalid+public+sync+key",
            state.config.mode.register_path
        ))
        .into_response();
    };
    match state.db.get_registered_user(&pubkey) {
        Ok(Some(rec)) if rec.email_hmac.as_deref() == Some(claims.email_hmac.as_str()) => {}
        Ok(Some(_)) => {
            return Redirect::to(&format!(
                "{}?key={}&err=Deletion+link+is+no+longer+valid+for+this+account",
                state.config.mode.register_path, pubkey
            ))
            .into_response();
        }
        Ok(None) => {
            return Redirect::to(&format!(
                "{}?key={}&err=Account+not+found",
                state.config.mode.register_path, pubkey
            ))
            .into_response();
        }
        Err(e) => {
            return Redirect::to(&format!(
                "{}?err={}",
                state.config.mode.register_path,
                url_encode(&e.to_string())
            ))
            .into_response();
        }
    }
    match state.db.consume_action_jti(&claims.jti, claims.exp, now) {
        Ok(true) => {}
        _ => {
            return Redirect::to(&format!(
                "{}?err=Deletion+link+already+used",
                state.config.mode.register_path
            ))
            .into_response();
        }
    }

    match state.db.delete_account_and_data(&pubkey, false) {
        Ok((slots, media, _)) => Redirect::to(&format!(
            "{}?key={}&msg={}",
            state.config.mode.register_path,
            pubkey,
            url_encode(&format!(
                "Account and {} slot(s), {} media blob(s) permanently deleted.",
                slots, media
            ))
        ))
        .into_response(),
        Err(e) => Redirect::to(&format!(
            "{}?err={}",
            state.config.mode.register_path,
            url_encode(&e.to_string())
        ))
        .into_response(),
    }
}

#[derive(Deserialize)]
struct AdminPageQuery {
    #[serde(default)]
    msg: Option<String>,
    #[serde(default)]
    err: Option<String>,
}

async fn admin_dashboard(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<AdminPageQuery>,
) -> Response {
    if state.config.security.admin_token_hash.trim().is_empty() {
        let html = layout_html(
            "Admin Setup Required",
            &state.config.mode.service_name,
            &state.config.mode.operator_contact,
            r#"<div class="card"><h2>Admin Dashboard Locked</h2><p class="muted">Configure <code>security.admin_token_hash</code> in <code>config.toml</code> (generate via <code>humoco-sync-server hash-token</code>).</p></div>"#,
        );
        return html_response(StatusCode::SERVICE_UNAVAILABLE, html);
    }

    let Some(sid) = extract_admin_session_cookie(&headers)
        .filter(|id| state.rate_limiter.validate_admin_session(id))
    else {
        let mut body = String::new();
        if let Some(ref e) = q.err {
            let _ = write!(body, r#"<div class="alert err">{}</div>"#, escape_html(e));
        }
        body.push_str(
            r#"<div class="card"><h2>Admin Login</h2>
            <form method="POST" action="/admin/login">
              <label>Operator Admin Token</label>
              <input type="password" name="token" required autofocus>
              <button type="submit">Sign In</button>
            </form></div>"#,
        );
        return html_response(
            StatusCode::OK,
            layout_html(
                "Admin Login",
                &state.config.mode.service_name,
                &state.config.mode.operator_contact,
                &body,
            ),
        );
    };

    let csrf = generate_session_csrf_pair(state.db.pepper(), &sid);
    let now = unix_now();
    let stats = state.db.admin_status(&state.config, now);
    let users = state
        .db
        .list_admin_users(&state.config, now)
        .unwrap_or_default();
    let codes = state.db.list_redeem_codes().unwrap_or_default();

    let mut body = String::new();
    if let Some(ref m) = q.msg {
        let _ = write!(body, r#"<div class="alert ok">{}</div>"#, escape_html(m));
    }
    if let Some(ref e) = q.err {
        let _ = write!(body, r#"<div class="alert err">{}</div>"#, escape_html(e));
    }

    let _ = write!(
        body,
        r#"<div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:1rem;">
        <span class="badge ok">Authenticated Operator</span>
        <form method="POST" action="/admin/logout" style="margin:0;">
          <input type="hidden" name="csrf" value="{csrf}">
          <button type="submit" class="secondary" style="margin:0;">Sign Out</button>
        </form></div>"#,
        csrf = escape_html(&csrf)
    );

    if let Ok(st) = stats {
        let _ = write!(
            body,
            r#"<div class="card"><h2>Storage &amp; Hybrid Pool Overview</h2>
            <div class="row">
              <div><p><strong>Total Used:</strong> {} / {}</p><p><strong>Free Pool:</strong> {} / {}</p></div>
              <div><p><strong>Admin App Friends:</strong> {} (in <code>index.json</code>)</p><p><strong>Registered Accounts:</strong> {} (<em>O(1) slot_id</em>)</p></div>
            </div>
            <p class="muted">Total stored items (slots + media): {}</p></div>"#,
            format_bytes(st.used_bytes),
            format_bytes(st.max_bytes),
            format_bytes(st.free_pool_used_bytes),
            format_bytes(st.free_pool_max_bytes),
            st.admin_members_count,
            st.registered_users_count,
            st.slot_count
        );
    }

    // Add/Upgrade user + Generate Code cards
    let mut profile_opts = String::new();
    for name in state.config.profiles.keys() {
        let _ = write!(
            profile_opts,
            r#"<option value="{}">{}</option>"#,
            escape_html(name),
            escape_html(name)
        );
    }
    let _ = write!(
        body,
        r#"<div class="row">
          <div class="card">
            <h2>Assign / Upgrade User Profile</h2>
            <form method="POST" action="/admin/users/profile">
              <input type="hidden" name="csrf" value="{csrf}">
              <label>Sync Pubkey (64 hex)</label>
              <input name="pubkey" placeholder="64-hex key" required>
              <label>Profile</label>
              <select name="profile">{profile_opts}</select>
              <label>Duration Days (empty = permanent)</label>
              <input name="duration_days" type="number" min="1" placeholder="365">
              <button type="submit">Save Profile</button>
            </form>
          </div>
          <div class="card">
            <h2>Generate Redeem Codes</h2>
            <form method="POST" action="/admin/codes">
              <input type="hidden" name="csrf" value="{csrf}">
              <label>Profile</label>
              <select name="profile">{profile_opts}</select>
              <label>Count</label>
              <input name="count" type="number" min="1" max="100" value="1">
              <label>Duration Days (empty = permanent)</label>
              <input name="duration_days" type="number" min="1" placeholder="365">
              <label>Note</label>
              <input name="note" placeholder="Optional order/campaign reference">
              <button type="submit">Create Codes</button>
            </form>
          </div>
        </div>"#,
        csrf = escape_html(&csrf),
        profile_opts = profile_opts
    );

    // Users table
    body.push_str(r#"<div class="card"><h2>Registered Users</h2><table><thead><tr><th>Pubkey</th><th>Profile</th><th>Usage</th><th>Status</th><th>Actions</th></tr></thead><tbody>"#);
    for u in &users {
        let short_pk = format_short_pubkey(&u.pubkey);
        let next_status = if u.status == AccountStatus::Active {
            "suspended"
        } else {
            "active"
        };
        let status_label = if u.status == AccountStatus::Active {
            "Suspend"
        } else {
            "Activate"
        };
        let email_info = u
            .contact_email
            .as_deref()
            .map(|e| format!("<br><span class=\"muted\">{}</span>", escape_html(e)))
            .unwrap_or_else(|| {
                if u.has_email_hmac {
                    "<br><span class=\"muted\">email_hmac (Zero-PII)</span>".to_string()
                } else {
                    String::new()
                }
            });
        let _ = write!(
            body,
            r#"<tr><td><code>{short_pk}</code>{email_info}</td>
            <td>{}</td>
            <td>{} ({} slots, {} media)</td>
            <td>{:?}</td>
            <td>
              <form method="POST" action="/admin/users/status" style="display:inline;">
                <input type="hidden" name="csrf" value="{csrf}">
                <input type="hidden" name="pubkey" value="{pk}">
                <input type="hidden" name="status" value="{next_status}">
                <button type="submit" class="secondary" style="margin:0;padding:.25rem .5rem;font-size:.78rem;">{status_label}</button>
              </form>
              <form method="POST" action="/admin/users/delete" style="display:inline;">
                <input type="hidden" name="csrf" value="{csrf}">
                <input type="hidden" name="pubkey" value="{pk}">
                <button type="submit" class="danger" style="margin:0;padding:.25rem .5rem;font-size:.78rem;">Delete</button>
              </form>
            </td></tr>"#,
            escape_html(&u.effective_profile),
            format_bytes(u.used_bytes),
            u.slot_count,
            u.media_count,
            u.status,
            csrf = escape_html(&csrf),
            pk = escape_html(&u.pubkey),
            short_pk = escape_html(&short_pk),
            email_info = email_info,
            next_status = next_status,
            status_label = status_label
        );
    }
    body.push_str("</tbody></table></div>");

    // Redeem codes table
    body.push_str(r#"<div class="card"><h2>Redeem Codes</h2><table><thead><tr><th>Code</th><th>Profile</th><th>Uses</th><th>Duration</th><th>Note</th></tr></thead><tbody>"#);
    for c in &codes {
        let dur = c
            .duration_days
            .map(|d| format!("{}d", d))
            .unwrap_or_else(|| "permanent".to_string());
        let _ = write!(
            body,
            r#"<tr><td><code>{}</code></td><td>{}</td><td>{}/{}</td><td>{}</td><td>{}</td></tr>"#,
            escape_html(&c.code),
            escape_html(&c.profile),
            c.used_count,
            c.max_uses,
            dur,
            escape_html(c.note.as_deref().unwrap_or(""))
        );
    }
    body.push_str("</tbody></table></div>");

    html_response(
        StatusCode::OK,
        layout_html(
            "Admin Dashboard",
            &state.config.mode.service_name,
            &state.config.mode.operator_contact,
            &body,
        ),
    )
}

#[derive(Deserialize)]
struct AdminLoginForm {
    token: String,
}

async fn admin_login_submit(
    State(state): State<AppState>,
    peer: Option<ConnectInfo<SocketAddr>>,
    headers: HeaderMap,
    Form(form): Form<AdminLoginForm>,
) -> Response {
    let ip = extract_client_ip(
        peer.map(|ConnectInfo(s)| s),
        &headers,
        state.config.server.trusted_proxy_hops,
    );
    if !state.rate_limiter.allow_ip(ip) {
        return Redirect::to("/admin?err=Rate+limit+exceeded").into_response();
    }
    if !state
        .token_verifier
        .verify_token(&state.config.security.admin_token_hash, form.token.trim())
    {
        return Redirect::to("/admin?err=Invalid+admin+token").into_response();
    }
    let sid = random_hex(24);
    state.rate_limiter.create_admin_session(sid.clone(), 3600);
    let secure = if state.config.server.public_base_url.starts_with("https://") {
        "; Secure"
    } else {
        ""
    };
    let cookie = format!(
        "{}={}; HttpOnly; SameSite=Strict; Path=/admin{}",
        ADMIN_SESSION_COOKIE, sid, secure
    );
    let mut resp = Redirect::to("/admin").into_response();
    if let Ok(hv) = HeaderValue::from_str(&cookie) {
        resp.headers_mut().insert(header::SET_COOKIE, hv);
    }
    resp
}

#[derive(Deserialize)]
struct CsrfOnlyForm {
    csrf: String,
}

async fn admin_logout_submit(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<CsrfOnlyForm>,
) -> Response {
    if let Some(sid) = verify_admin_cookie_and_csrf(&state, &headers, &form.csrf) {
        state.rate_limiter.revoke_admin_session(&sid);
    }
    let secure = if state.config.server.public_base_url.starts_with("https://") {
        "; Secure"
    } else {
        ""
    };
    let cookie = format!(
        "{}=; Max-Age=0; HttpOnly; SameSite=Strict; Path=/admin{}",
        ADMIN_SESSION_COOKIE, secure
    );
    let mut resp = Redirect::to("/admin").into_response();
    if let Ok(hv) = HeaderValue::from_str(&cookie) {
        resp.headers_mut().insert(header::SET_COOKIE, hv);
    }
    resp
}

#[derive(Deserialize)]
struct AdminProfileForm {
    csrf: String,
    pubkey: String,
    profile: String,
    #[serde(default)]
    duration_days: String,
}

async fn admin_user_profile_submit(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<AdminProfileForm>,
) -> Response {
    if verify_admin_cookie_and_csrf(&state, &headers, &form.csrf).is_none() {
        return Redirect::to("/admin?err=Session+expired").into_response();
    }
    let Some(pk) = normalize_pubkey_hex(&form.pubkey) else {
        return Redirect::to("/admin?err=Invalid+pubkey").into_response();
    };
    let dur = match parse_optional_positive_days(&form.duration_days) {
        Ok(d) => d,
        Err(msg) => {
            return Redirect::to(&format!("/admin?err={}", url_encode(msg))).into_response();
        }
    };
    let now = unix_now();
    match state.db.register_or_upgrade_user(
        &state.config,
        &pk,
        form.profile.trim(),
        None,
        dur,
        "admin",
        now,
    ) {
        Ok(_) => Redirect::to("/admin?msg=User+profile+updated").into_response(),
        Err(e) => {
            Redirect::to(&format!("/admin?err={}", url_encode(&e.to_string()))).into_response()
        }
    }
}

#[derive(Deserialize)]
struct AdminStatusForm {
    csrf: String,
    pubkey: String,
    status: String,
}

async fn admin_user_status_submit(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<AdminStatusForm>,
) -> Response {
    if verify_admin_cookie_and_csrf(&state, &headers, &form.csrf).is_none() {
        return Redirect::to("/admin?err=Session+expired").into_response();
    }
    let Some(pk) = normalize_pubkey_hex(&form.pubkey) else {
        return Redirect::to("/admin?err=Invalid+pubkey").into_response();
    };
    let st = match form.status.as_str() {
        "active" => AccountStatus::Active,
        "suspended" => AccountStatus::Suspended,
        _ => return Redirect::to("/admin?err=Invalid+status").into_response(),
    };
    match state.db.set_user_status(&pk, st, unix_now()) {
        Ok(()) => Redirect::to("/admin?msg=User+status+updated").into_response(),
        Err(e) => {
            Redirect::to(&format!("/admin?err={}", url_encode(&e.to_string()))).into_response()
        }
    }
}

#[derive(Deserialize)]
struct AdminDeleteUserForm {
    csrf: String,
    pubkey: String,
}

async fn admin_user_delete_submit(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<AdminDeleteUserForm>,
) -> Response {
    if verify_admin_cookie_and_csrf(&state, &headers, &form.csrf).is_none() {
        return Redirect::to("/admin?err=Session+expired").into_response();
    }
    let Some(pk) = normalize_pubkey_hex(&form.pubkey) else {
        return Redirect::to("/admin?err=Invalid+pubkey").into_response();
    };
    match state.db.delete_account_and_data(&pk, false) {
        Ok(_) => Redirect::to("/admin?msg=User+deleted").into_response(),
        Err(e) => {
            Redirect::to(&format!("/admin?err={}", url_encode(&e.to_string()))).into_response()
        }
    }
}

#[derive(Deserialize)]
struct AdminCreateCodeForm {
    csrf: String,
    profile: String,
    #[serde(default)]
    count: String,
    #[serde(default)]
    duration_days: String,
    #[serde(default)]
    note: String,
}

async fn admin_create_code_submit(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<AdminCreateCodeForm>,
) -> Response {
    if verify_admin_cookie_and_csrf(&state, &headers, &form.csrf).is_none() {
        return Redirect::to("/admin?err=Session+expired").into_response();
    }
    let count = match form.count.trim() {
        "" => 1usize,
        raw => match raw.parse::<usize>() {
            Ok(n) if n > 0 => n.clamp(1, 100),
            _ => {
                return Redirect::to("/admin?err=Code+count+must+be+a+positive+integer")
                    .into_response();
            }
        },
    };
    let dur = match parse_optional_positive_days(&form.duration_days) {
        Ok(d) => d,
        Err(msg) => {
            return Redirect::to(&format!("/admin?err={}", url_encode(msg))).into_response();
        }
    };
    let note = Some(form.note.trim().to_string()).filter(|s| !s.is_empty());
    let now = unix_now();
    match state.db.create_redeem_codes(
        &state.config,
        count,
        form.profile.trim(),
        dur,
        1,
        None,
        note,
        None,
        now,
    ) {
        Ok(created) => {
            let preview: Vec<_> = created.iter().take(5).map(|c| c.code.as_str()).collect();
            Redirect::to(&format!(
                "/admin?msg={}",
                url_encode(&format!(
                    "Created {} code(s): {}",
                    created.len(),
                    preview.join(", ")
                ))
            ))
            .into_response()
        }
        Err(e) => {
            Redirect::to(&format!("/admin?err={}", url_encode(&e.to_string()))).into_response()
        }
    }
}

fn extract_admin_session_cookie(headers: &HeaderMap) -> Option<String> {
    for val in headers.get_all(header::COOKIE) {
        let Ok(raw) = val.to_str() else {
            continue;
        };
        for part in raw.split(';') {
            if let Some((k, v)) = part.trim().split_once('=') {
                if k.trim() == ADMIN_SESSION_COOKIE && !v.trim().is_empty() {
                    return Some(v.trim().to_string());
                }
            }
        }
    }
    None
}

fn format_short_pubkey(pk: &str) -> String {
    let chars: Vec<char> = pk.chars().collect();
    if chars.len() >= 18 {
        let head: String = chars[..10].iter().collect();
        let tail: String = chars[chars.len() - 6..].iter().collect();
        format!("{}...{}", head, tail)
    } else {
        pk.to_string()
    }
}

fn parse_optional_positive_days(raw: &str) -> Result<Option<u32>, &'static str> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Ok(None);
    }
    match trimmed.parse::<u32>() {
        Ok(d) if d > 0 => Ok(Some(d)),
        _ => Err("Duration days must be a positive integer (or leave empty for permanent)"),
    }
}

fn verify_admin_cookie_and_csrf(
    state: &AppState,
    headers: &HeaderMap,
    csrf: &str,
) -> Option<String> {
    let sid = extract_admin_session_cookie(headers)?;
    if !state.rate_limiter.validate_admin_session(&sid) {
        return None;
    }
    let expected = generate_session_csrf_pair(state.db.pepper(), &sid);
    if constant_time_eq_str(csrf.trim(), &expected) {
        Some(sid)
    } else {
        None
    }
}

fn ensure_pubkey_unregistered_for_public_gate(state: &AppState, pubkey: &str) -> Option<Response> {
    match state.db.get_registered_user(pubkey) {
        Ok(Some(rec)) => {
            let msg = if rec.status == AccountStatus::Suspended {
                "Account+is+suspended"
            } else {
                "Public+key+is+already+registered"
            };
            Some(
                Redirect::to(&format!(
                    "{}?key={}&err={}",
                    state.config.mode.register_path, pubkey, msg
                ))
                .into_response(),
            )
        }
        Ok(None) => None,
        Err(e) => Some(
            Redirect::to(&format!(
                "{}?key={}&err={}",
                state.config.mode.register_path,
                pubkey,
                url_encode(&e.to_string())
            ))
            .into_response(),
        ),
    }
}

fn url_encode(s: &str) -> String {
    form_urlencoded::byte_serialize(s.as_bytes()).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::Request;
    use tempfile::TempDir;
    use tower::ServiceExt;

    #[tokio::test]
    async fn test_s05_web_routes_panic_safety_and_https_logout_secure_cookie() {
        let dir = TempDir::new().unwrap();
        let mut cfg = Config::default();
        cfg.server.db_path = dir.path().join("web_unit.redb");
        cfg.server.public_base_url = "https://sync.example.org".to_string();
        cfg.mode.enable_admin_app = false;
        cfg.mode.enable_public_registration = true;
        cfg.mode.registration_gates = vec!["email".to_string()];
        // Simulate unvalidated Config with missing default_public_profile
        cfg.mode.default_public_profile = "missing_profile".to_string();

        let state = AppState::from_config(cfg).unwrap();
        let app = web_router(&state.config).with_state(state.clone());

        let resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/register")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        // Test HTTPS logout emits Secure attribute
        let sid = "test_session_id_123456".to_string();
        state.rate_limiter.create_admin_session(sid.clone(), 3600);
        let csrf = generate_session_csrf_pair(state.db.pepper(), &sid);
        let form_body = format!("csrf={}", url_encode(&csrf));
        let logout_resp = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/admin/logout")
                    .header(header::COOKIE, format!("{}={}", ADMIN_SESSION_COOKIE, sid))
                    .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                    .body(Body::from(form_body))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(logout_resp.status(), StatusCode::SEE_OTHER);
        let sc = logout_resp
            .headers()
            .get(header::SET_COOKIE)
            .unwrap()
            .to_str()
            .unwrap();
        assert!(
            sc.contains("; Secure"),
            "HTTPS logout must include ; Secure, got: {sc}"
        );

        assert_eq!(format_short_pubkey("short"), "short");
        assert_eq!(format_short_pubkey("äöüß"), "äöüß");
        assert_eq!(format_short_pubkey(&"a".repeat(64)), "aaaaaaaaaa...aaaaaa");
    }
}
