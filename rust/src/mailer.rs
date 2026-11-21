use std::sync::Arc;
use std::time::Duration;

use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use parking_lot::Mutex;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;
use tokio_rustls::rustls;
use tokio_rustls::TlsConnector;
use tracing::{info, warn};

use crate::config::EmailConfig;

const SMTP_IO_TIMEOUT: Duration = Duration::from_secs(15);
const MAX_SMTP_LINE_BYTES: usize = 4096;
const MAX_SMTP_CONTINUATION_LINES: usize = 64;

#[derive(Debug, Clone)]
pub struct RecordedMail {
    pub to: String,
    pub subject: String,
    pub body: String,
}

pub struct Mailer {
    cfg: EmailConfig,
    recorded: Mutex<Vec<RecordedMail>>,
    io_timeout: Duration,
}

impl Mailer {
    pub fn new(cfg: EmailConfig) -> Self {
        Self {
            cfg,
            recorded: Mutex::new(Vec::new()),
            io_timeout: SMTP_IO_TIMEOUT,
        }
    }

    #[cfg(test)]
    fn with_timeout(mut self, timeout: Duration) -> Self {
        self.io_timeout = timeout;
        self
    }

    pub fn take_recorded(&self) -> Vec<RecordedMail> {
        let mut g = self.recorded.lock();
        std::mem::take(&mut *g)
    }

    pub fn recorded_snapshot(&self) -> Vec<RecordedMail> {
        self.recorded.lock().clone()
    }

    pub async fn send_mail(&self, to: &str, subject: &str, body: &str) -> Result<(), String> {
        if !self.cfg.enabled {
            return Err("Email delivery is disabled (email.enabled = false)".to_string());
        }
        let to_trimmed = to.trim();
        if !is_safe_smtp_addr(to_trimmed) || subject.chars().any(|c| c.is_control()) {
            return Err("Invalid email header characters".to_string());
        }

        match self.cfg.transport.as_str() {
            "log" | "" => {
                if !is_safe_smtp_addr(self.cfg.from_address.trim()) {
                    return Err("Invalid configured sender email address".to_string());
                }
                info!(to = %to_trimmed, subject = %subject, body = %body, "Email dispatched via log transport");
                let mut g = self.recorded.lock();
                if g.len() >= 100 {
                    g.remove(0);
                }
                g.push(RecordedMail {
                    to: to_trimmed.to_string(),
                    subject: subject.to_string(),
                    body: body.to_string(),
                });
                Ok(())
            }
            "sendmail" => self.send_via_sendmail(to_trimmed, subject, body).await,
            "smtp" => self.send_via_smtp(to_trimmed, subject, body).await,
            other => Err(format!("Unsupported email transport '{}'", other)),
        }
    }

    async fn send_via_sendmail(&self, to: &str, subject: &str, body: &str) -> Result<(), String> {
        let from_addr = self.cfg.from_address.trim();
        if !is_safe_smtp_addr(from_addr) {
            return Err("Invalid configured sender email address".to_string());
        }
        let msg = format!(
            "From: {} <{}>\r\nTo: {}\r\nSubject: {}\r\nContent-Type: text/plain; charset=UTF-8\r\n\r\n{}\r\n",
            sanitize_header(&self.cfg.from_name),
            from_addr,
            to,
            subject,
            dot_stuff_body(body)
        );
        let mut child = tokio::process::Command::new(&self.cfg.sendmail_path)
            .arg("-t")
            .arg("-i")
            .stdin(std::process::Stdio::piped())
            .kill_on_drop(true)
            .spawn()
            .map_err(|e| format!("Failed to execute sendmail: {}", e))?;

        let status = tokio::time::timeout(self.io_timeout, async {
            if let Some(mut stdin) = child.stdin.take() {
                stdin
                    .write_all(msg.as_bytes())
                    .await
                    .map_err(|e| format!("Failed to write to sendmail stdin: {}", e))?;
            }
            child
                .wait()
                .await
                .map_err(|e| format!("Sendmail wait failed: {}", e))
        })
        .await
        .map_err(|_| "Sendmail timed out".to_string())??;

        if !status.success() {
            return Err(format!("Sendmail exited with status {}", status));
        }
        Ok(())
    }

    async fn send_via_smtp(&self, to: &str, subject: &str, body: &str) -> Result<(), String> {
        let from_addr = self.cfg.from_address.trim();
        if !is_safe_smtp_addr(from_addr) {
            return Err("Invalid configured sender email address".to_string());
        }
        let host = self.cfg.smtp_host.trim();
        if host.is_empty() || self.cfg.smtp_port == 0 {
            return Err("Invalid SMTP host or port".to_string());
        }
        let tls_mode = self.cfg.smtp_tls_mode.trim();
        if !matches!(tls_mode, "tls" | "starttls" | "plain") {
            return Err(format!("Unsupported smtp_tls_mode '{}'", tls_mode));
        }

        tokio::time::timeout(self.io_timeout, async {
            let stream = TcpStream::connect((host, self.cfg.smtp_port))
                .await
                .map_err(|e| format!("SMTP connect failed: {}", e))?;

            match tls_mode {
                "tls" => {
                    let connector = build_tls_connector();
                    let server_name = rustls::pki_types::ServerName::try_from(host.to_string())
                        .map_err(|_| "Invalid SMTP server hostname".to_string())?;
                    let tls = connector
                        .connect(server_name, stream)
                        .await
                        .map_err(|e| format!("SMTP TLS handshake failed: {}", e))?;
                    self.run_smtp_session(tls, false, from_addr, to, subject, body)
                        .await
                }
                "starttls" => {
                    let mut reader = BufReader::new(stream);
                    read_smtp_expect(&mut reader, 220).await?;
                    write_smtp_line(&mut reader, "EHLO localhost").await?;
                    read_smtp_expect(&mut reader, 250).await?;
                    write_smtp_line(&mut reader, "STARTTLS").await?;
                    read_smtp_expect(&mut reader, 220).await?;
                    let stream = reader.into_inner();
                    let connector = build_tls_connector();
                    let server_name = rustls::pki_types::ServerName::try_from(host.to_string())
                        .map_err(|_| "Invalid SMTP server hostname".to_string())?;
                    let tls = connector
                        .connect(server_name, stream)
                        .await
                        .map_err(|e| format!("SMTP STARTTLS handshake failed: {}", e))?;
                    self.run_smtp_session(tls, true, from_addr, to, subject, body)
                        .await
                }
                "plain" => {
                    warn!("Using plaintext SMTP without TLS");
                    self.run_smtp_session(stream, false, from_addr, to, subject, body)
                        .await
                }
                _ => Err(format!("Unsupported smtp_tls_mode '{}'", tls_mode)),
            }
        })
        .await
        .map_err(|_| "SMTP operation timed out".to_string())?
    }

    async fn run_smtp_session<S>(
        &self,
        stream: S,
        already_upgraded: bool,
        from_addr: &str,
        to: &str,
        subject: &str,
        body: &str,
    ) -> Result<(), String>
    where
        S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
    {
        let mut reader = BufReader::new(stream);
        if !already_upgraded {
            read_smtp_expect(&mut reader, 220).await?;
        }
        write_smtp_line(&mut reader, "EHLO localhost").await?;
        read_smtp_expect(&mut reader, 250).await?;

        if !self.cfg.smtp_username.is_empty() {
            let auth_plain = format!("\0{}\0{}", self.cfg.smtp_username, self.cfg.smtp_password);
            let encoded = STANDARD.encode(auth_plain.as_bytes());
            write_smtp_line(&mut reader, &format!("AUTH PLAIN {}", encoded)).await?;
            read_smtp_expect(&mut reader, 235).await?;
        }

        write_smtp_line(&mut reader, &format!("MAIL FROM:<{}>", from_addr)).await?;
        read_smtp_expect(&mut reader, 250).await?;
        write_smtp_line(&mut reader, &format!("RCPT TO:<{}>", to)).await?;
        read_smtp_expect(&mut reader, 250).await?;
        write_smtp_line(&mut reader, "DATA").await?;
        read_smtp_expect(&mut reader, 354).await?;

        let escaped_body = dot_stuff_body(body);
        let payload = format!(
            "From: {} <{}>\r\nTo: {}\r\nSubject: {}\r\nMIME-Version: 1.0\r\nContent-Type: text/plain; charset=UTF-8\r\n\r\n{}\r\n.\r\n",
            sanitize_header(&self.cfg.from_name),
            from_addr,
            to,
            subject,
            escaped_body
        );
        reader
            .get_mut()
            .write_all(payload.as_bytes())
            .await
            .map_err(|e| format!("SMTP write body failed: {}", e))?;
        reader
            .get_mut()
            .flush()
            .await
            .map_err(|e| format!("SMTP flush failed: {}", e))?;
        read_smtp_expect(&mut reader, 250).await?;

        let _ = write_smtp_line(&mut reader, "QUIT").await;
        Ok(())
    }
}

fn build_tls_connector() -> TlsConnector {
    let mut root_store = rustls::RootCertStore::empty();
    root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let config = rustls::ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();
    TlsConnector::from(Arc::new(config))
}

async fn write_smtp_line<S>(reader: &mut BufReader<S>, line: &str) -> Result<(), String>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    if line.chars().any(|c| c == '\r' || c == '\n' || c == '\0') {
        return Err("Invalid SMTP command line characters".to_string());
    }
    reader
        .get_mut()
        .write_all(format!("{}\r\n", line).as_bytes())
        .await
        .map_err(|e| format!("SMTP write failed: {}", e))?;
    reader
        .get_mut()
        .flush()
        .await
        .map_err(|e| format!("SMTP flush failed: {}", e))
}

async fn read_bounded_smtp_line<S>(reader: &mut BufReader<S>) -> Result<Vec<u8>, String>
where
    S: tokio::io::AsyncRead + Unpin,
{
    let mut line = Vec::new();
    loop {
        let buf = reader
            .fill_buf()
            .await
            .map_err(|e| format!("SMTP read failed: {}", e))?;
        if buf.is_empty() {
            if line.is_empty() {
                return Err("SMTP connection closed unexpectedly".to_string());
            }
            return Ok(line);
        }
        if let Some(pos) = buf.iter().position(|&b| b == b'\n') {
            let take_len = pos + 1;
            if line.len().saturating_add(take_len) > MAX_SMTP_LINE_BYTES {
                return Err("SMTP response line too long".to_string());
            }
            line.extend_from_slice(&buf[..take_len]);
            reader.consume(take_len);
            return Ok(line);
        }
        if line.len().saturating_add(buf.len()) > MAX_SMTP_LINE_BYTES {
            return Err("SMTP response line too long".to_string());
        }
        let n = buf.len();
        line.extend_from_slice(buf);
        reader.consume(n);
    }
}

async fn read_smtp_expect<S>(reader: &mut BufReader<S>, expected_code: u16) -> Result<(), String>
where
    S: tokio::io::AsyncRead + Unpin,
{
    let mut continuations = 0usize;
    loop {
        let bytes = read_bounded_smtp_line(reader).await?;
        if bytes.len() < 4 || !bytes[..3].iter().all(|b| b.is_ascii_digit()) {
            let preview = String::from_utf8_lossy(&bytes);
            return Err(format!("Malformed SMTP response: {}", preview.trim()));
        }
        let code_str = std::str::from_utf8(&bytes[..3]).unwrap_or("");
        let code: u16 = code_str
            .parse()
            .map_err(|_| format!("Invalid SMTP code: {}", code_str))?;
        let sep = bytes[3];
        if sep == b'-' {
            continuations += 1;
            if continuations > MAX_SMTP_CONTINUATION_LINES {
                return Err("Too many SMTP multiline continuation lines".to_string());
            }
            continue;
        }
        if !matches!(sep, b' ' | b'\r' | b'\n') {
            let preview = String::from_utf8_lossy(&bytes);
            return Err(format!("Malformed SMTP response: {}", preview.trim()));
        }
        if code != expected_code {
            let preview = String::from_utf8_lossy(&bytes);
            return Err(format!(
                "SMTP expected {} got {}",
                expected_code,
                preview.trim()
            ));
        }
        return Ok(());
    }
}

fn is_safe_smtp_addr(addr: &str) -> bool {
    if addr.is_empty()
        || addr.len() > 254
        || addr
            .chars()
            .any(|c| c.is_control() || c.is_whitespace() || matches!(c, '<' | '>' | ',' | ';'))
    {
        return false;
    }
    let Some((local, domain)) = addr.split_once('@') else {
        return false;
    };
    !local.is_empty() && !domain.is_empty() && !domain.contains('@')
}

fn dot_stuff_body(body: &str) -> String {
    body.replace("\r\n", "\n")
        .replace('\r', "\n")
        .split('\n')
        .map(|l| {
            if l.starts_with('.') {
                format!(".{}", l)
            } else {
                l.to_string()
            }
        })
        .collect::<Vec<_>>()
        .join("\r\n")
}

fn sanitize_header(s: &str) -> String {
    s.chars()
        .map(|c| {
            if c.is_control() || matches!(c, '<' | '>') {
                ' '
            } else {
                c
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    fn base_smtp_cfg(host: &str, port: u16, tls_mode: &str) -> EmailConfig {
        EmailConfig {
            enabled: true,
            transport: "smtp".to_string(),
            smtp_host: host.to_string(),
            smtp_port: port,
            smtp_username: "user".to_string(),
            smtp_password: "secret".to_string(),
            smtp_tls_mode: tls_mode.to_string(),
            from_address: "noreply@localhost".to_string(),
            from_name: "HuMoCo\x00Sync".to_string(),
            token_ttl_minutes: 30,
            sendmail_path: "/usr/sbin/sendmail".to_string(),
        }
    }

    #[tokio::test]
    async fn test_s05_mailer_rejects_unknown_tls_mode_injection_and_bare_cr_smuggling() {
        // 1. Unknown smtp_tls_mode must fail closed (NEVER downgrade to plaintext SMTP)
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let srv_task = tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            let _ = sock.write_all(b"220 mock ESMTP\r\n").await;
            let mut buf = [0u8; 512];
            let n = sock.read(&mut buf).await.unwrap_or(0);
            String::from_utf8_lossy(&buf[..n]).to_string()
        });
        let mailer = Mailer::new(base_smtp_cfg("127.0.0.1", port, "ssl"));
        let res = mailer.send_mail("user@example.org", "Test", "Hello").await;
        assert!(
            res.is_err(),
            "Unrecognized smtp_tls_mode 'ssl' must fail closed, never downgrade to plaintext"
        );
        // Ensure no EHLO/AUTH PLAIN credentials were sent
        srv_task.abort();

        // 2. Injection / control chars in recipient, subject, from_address must be rejected
        // Also verify email.enabled = false blocks dispatch cleanly
        let disabled_mailer = Mailer::new(EmailConfig::default());
        assert!(
            disabled_mailer
                .send_mail("alice@example.org", "Subj", "Body")
                .await
                .is_err(),
            "email.enabled = false must reject mail dispatch"
        );

        let log_mailer = Mailer::new(EmailConfig {
            enabled: true,
            ..Default::default()
        });
        for bad_to in [
            "alice@example.org,bcc@evil.org",
            "alice@example.org;bcc@evil.org",
            "alice<x>@example.org",
            "alice\0@example.org",
            "alice@example.org\r\nBcc: evil@evil.org",
        ] {
            assert!(
                log_mailer.send_mail(bad_to, "Subj", "Body").await.is_err(),
                "Expected send_mail to reject recipient {:?}",
                bad_to
            );
        }
        assert!(log_mailer
            .send_mail("alice@example.org", "Subj\0Inject", "Body")
            .await
            .is_err());

        let bad_from_cfg = EmailConfig {
            enabled: true,
            from_address: "bad>addr@example.org".to_string(),
            ..Default::default()
        };
        let bad_from_mailer = Mailer::new(bad_from_cfg);
        assert!(bad_from_mailer
            .send_mail("alice@example.org", "Subj", "Body")
            .await
            .is_err());

        // 3. Bare-CR dot-stuffing smuggling prevention
        assert_eq!(dot_stuff_body("hello\r.\rworld"), "hello\r\n..\r\nworld");

        // 4. Explicit 'plain' SMTP mode still works cleanly and strips control chars from From name
        let plain_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let plain_port = plain_listener.local_addr().unwrap().port();
        let plain_srv = tokio::spawn(async move {
            let (sock, _) = plain_listener.accept().await.unwrap();
            let (rd, mut wr) = sock.into_split();
            let mut br = BufReader::new(rd);
            wr.write_all(b"220 mock ESMTP\r\n").await.unwrap();
            let mut line = String::new();
            let mut transcript = String::new();
            loop {
                line.clear();
                if br.read_line(&mut line).await.unwrap() == 0 {
                    break;
                }
                transcript.push_str(&line);
                if line.starts_with("EHLO") {
                    wr.write_all(b"250-mock\r\n250 OK\r\n").await.unwrap();
                } else if line.starts_with("AUTH ") {
                    wr.write_all(b"235 OK\r\n").await.unwrap();
                } else if line.starts_with("MAIL ") || line.starts_with("RCPT ") {
                    wr.write_all(b"250 OK\r\n").await.unwrap();
                } else if line.starts_with("DATA") {
                    wr.write_all(b"354 End data\r\n").await.unwrap();
                    loop {
                        line.clear();
                        br.read_line(&mut line).await.unwrap();
                        transcript.push_str(&line);
                        if line == ".\r\n" {
                            wr.write_all(b"250 Queued\r\n").await.unwrap();
                            break;
                        }
                    }
                } else if line.starts_with("QUIT") {
                    wr.write_all(b"221 Bye\r\n").await.unwrap();
                    break;
                }
            }
            transcript
        });
        let plain_mailer = Mailer::new(base_smtp_cfg("127.0.0.1", plain_port, "plain"));
        plain_mailer
            .send_mail("alice@example.org", "Hi", "line1\r.\rline2")
            .await
            .unwrap();
        let tx = plain_srv.await.unwrap();
        assert!(tx.contains("line1\r\n..\r\nline2\r\n.\r\n"));
        assert!(!tx.contains('\0'));
    }

    #[tokio::test]
    async fn test_s05_mailer_bounded_smtp_reader_prevents_utf8_panic_and_flood() {
        // 1. Malformed / multibyte UTF-8 split at byte index 3 (b"25\xc3\xa9\n") must NOT panic!
        let l1 = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let p1 = l1.local_addr().unwrap().port();
        tokio::spawn(async move {
            let (mut sock, _) = l1.accept().await.unwrap();
            let _ = sock.write_all(b"25\xc3\xa9\n").await;
        });
        let m1 = Mailer::new(base_smtp_cfg("127.0.0.1", p1, "plain"));
        let res1 = m1.send_mail("alice@example.org", "Hi", "Body").await;
        assert!(res1.is_err());

        // 2. Excessive 250- continuation flood (> 64 lines before final 250 OK) must abort cleanly
        let l2 = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let p2 = l2.local_addr().unwrap().port();
        tokio::spawn(async move {
            let (sock, _) = l2.accept().await.unwrap();
            let (rd, mut wr) = sock.into_split();
            let mut br = BufReader::new(rd);
            let _ = wr.write_all(b"220 mock\r\n").await;
            let mut tmp = String::new();
            let _ = br.read_line(&mut tmp).await;
            for _ in 0..100 {
                if wr.write_all(b"250-flood\r\n").await.is_err() {
                    return;
                }
            }
            let _ = wr.write_all(b"250 OK\r\n").await;
        });
        let m2 = Mailer::new(base_smtp_cfg("127.0.0.1", p2, "plain"));
        let err2 = m2
            .send_mail("alice@example.org", "Hi", "Body")
            .await
            .unwrap_err();
        assert!(
            err2.contains("continuation")
                || err2.contains("multiline")
                || err2.contains("Too many"),
            "Expected multiline continuation cap error, got: {err2}"
        );

        // 3. Oversized line without newline must fail with line-length error without OOM
        let l3 = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let p3 = l3.local_addr().unwrap().port();
        tokio::spawn(async move {
            let (mut sock, _) = l3.accept().await.unwrap();
            let huge = vec![b'A'; 16_384];
            let _ = sock.write_all(&huge).await;
            tokio::time::sleep(std::time::Duration::from_secs(2)).await;
        });
        let m3 = Mailer::new(base_smtp_cfg("127.0.0.1", p3, "plain"));
        let err3 = m3
            .send_mail("alice@example.org", "Hi", "Body")
            .await
            .unwrap_err();
        assert!(
            err3.contains("too long") || err3.contains("line"),
            "Expected line length cap error, got: {err3}"
        );

        // 4. Stalled SMTP peer must time out cleanly instead of hanging indefinitely
        let l4 = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let p4 = l4.local_addr().unwrap().port();
        tokio::spawn(async move {
            let (_sock, _) = l4.accept().await.unwrap();
            tokio::time::sleep(Duration::from_secs(5)).await;
        });
        let m4 = Mailer::new(base_smtp_cfg("127.0.0.1", p4, "plain"))
            .with_timeout(Duration::from_millis(80));
        let err4 = m4
            .send_mail("alice@example.org", "Hi", "Body")
            .await
            .unwrap_err();
        assert!(
            err4.contains("timed out"),
            "Expected timeout error, got: {err4}"
        );
    }
}
