use std::sync::Arc;

use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use parking_lot::Mutex;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;
use tokio_rustls::rustls;
use tokio_rustls::TlsConnector;
use tracing::{info, warn};

use crate::config::EmailConfig;

#[derive(Debug, Clone)]
pub struct RecordedMail {
    pub to: String,
    pub subject: String,
    pub body: String,
}

pub struct Mailer {
    cfg: EmailConfig,
    recorded: Mutex<Vec<RecordedMail>>,
}

impl Mailer {
    pub fn new(cfg: EmailConfig) -> Self {
        Self {
            cfg,
            recorded: Mutex::new(Vec::new()),
        }
    }

    pub fn take_recorded(&self) -> Vec<RecordedMail> {
        let mut g = self.recorded.lock();
        std::mem::take(&mut *g)
    }

    pub fn recorded_snapshot(&self) -> Vec<RecordedMail> {
        self.recorded.lock().clone()
    }

    pub async fn send_mail(&self, to: &str, subject: &str, body: &str) -> Result<(), String> {
        if to.contains('\r') || to.contains('\n') || subject.contains('\r') || subject.contains('\n') {
            return Err("Invalid email header characters".to_string());
        }

        match self.cfg.transport.as_str() {
            "log" | "" => {
                info!(to = %to, subject = %subject, body = %body, "Email dispatched via log transport");
                let mut g = self.recorded.lock();
                if g.len() >= 100 {
                    g.remove(0);
                }
                g.push(RecordedMail {
                    to: to.to_string(),
                    subject: subject.to_string(),
                    body: body.to_string(),
                });
                Ok(())
            }
            "sendmail" => self.send_via_sendmail(to, subject, body).await,
            "smtp" => self.send_via_smtp(to, subject, body).await,
            other => Err(format!("Unsupported email transport '{}'", other)),
        }
    }

    async fn send_via_sendmail(&self, to: &str, subject: &str, body: &str) -> Result<(), String> {
        let msg = format!(
            "From: {} <{}>\r\nTo: {}\r\nSubject: {}\r\nContent-Type: text/plain; charset=UTF-8\r\n\r\n{}\r\n",
            sanitize_header(&self.cfg.from_name),
            self.cfg.from_address,
            to,
            subject,
            body
        );
        let mut child = tokio::process::Command::new(&self.cfg.sendmail_path)
            .arg("-t")
            .arg("-i")
            .stdin(std::process::Stdio::piped())
            .spawn()
            .map_err(|e| format!("Failed to execute sendmail: {}", e))?;

        if let Some(mut stdin) = child.stdin.take() {
            stdin
                .write_all(msg.as_bytes())
                .await
                .map_err(|e| format!("Failed to write to sendmail stdin: {}", e))?;
        }
        let status = child
            .wait()
            .await
            .map_err(|e| format!("Sendmail wait failed: {}", e))?;
        if !status.success() {
            return Err(format!("Sendmail exited with status {}", status));
        }
        Ok(())
    }

    async fn send_via_smtp(&self, to: &str, subject: &str, body: &str) -> Result<(), String> {
        let addr = format!("{}:{}", self.cfg.smtp_host, self.cfg.smtp_port);
        let stream = TcpStream::connect(&addr)
            .await
            .map_err(|e| format!("SMTP connect failed: {}", e))?;

        if self.cfg.smtp_tls_mode == "tls" {
            let connector = build_tls_connector();
            let server_name = rustls::pki_types::ServerName::try_from(self.cfg.smtp_host.clone())
                .map_err(|_| "Invalid SMTP server hostname".to_string())?;
            let tls = connector
                .connect(server_name, stream)
                .await
                .map_err(|e| format!("SMTP TLS handshake failed: {}", e))?;
            return self.run_smtp_session(tls, false, to, subject, body).await;
        }

        if self.cfg.smtp_tls_mode == "starttls" {
            let mut reader = BufReader::new(stream);
            read_smtp_expect(&mut reader, 220).await?;
            write_smtp_line(&mut reader, "EHLO localhost").await?;
            read_smtp_expect(&mut reader, 250).await?;
            write_smtp_line(&mut reader, "STARTTLS").await?;
            read_smtp_expect(&mut reader, 220).await?;
            let stream = reader.into_inner();
            let connector = build_tls_connector();
            let server_name = rustls::pki_types::ServerName::try_from(self.cfg.smtp_host.clone())
                .map_err(|_| "Invalid SMTP server hostname".to_string())?;
            let tls = connector
                .connect(server_name, stream)
                .await
                .map_err(|e| format!("SMTP STARTTLS handshake failed: {}", e))?;
            return self.run_smtp_session(tls, true, to, subject, body).await;
        }

        warn!("Using plaintext SMTP without TLS");
        self.run_smtp_session(stream, false, to, subject, body).await
    }

    async fn run_smtp_session<S>(
        &self,
        stream: S,
        already_upgraded: bool,
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
            let auth_plain = format!(
                "\0{}\0{}",
                self.cfg.smtp_username, self.cfg.smtp_password
            );
            let encoded = STANDARD.encode(auth_plain.as_bytes());
            write_smtp_line(&mut reader, &format!("AUTH PLAIN {}", encoded)).await?;
            read_smtp_expect(&mut reader, 235).await?;
        }

        write_smtp_line(&mut reader, &format!("MAIL FROM:<{}>", self.cfg.from_address)).await?;
        read_smtp_expect(&mut reader, 250).await?;
        write_smtp_line(&mut reader, &format!("RCPT TO:<{}>", to)).await?;
        read_smtp_expect(&mut reader, 250).await?;
        write_smtp_line(&mut reader, "DATA").await?;
        read_smtp_expect(&mut reader, 354).await?;

        let escaped_body = dot_stuff_body(body);
        let payload = format!(
            "From: {} <{}>\r\nTo: {}\r\nSubject: {}\r\nMIME-Version: 1.0\r\nContent-Type: text/plain; charset=UTF-8\r\n\r\n{}\r\n.\r\n",
            sanitize_header(&self.cfg.from_name),
            self.cfg.from_address,
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

async fn read_smtp_expect<S>(reader: &mut BufReader<S>, expected_code: u16) -> Result<(), String>
where
    S: tokio::io::AsyncRead + Unpin,
{
    let mut line = String::new();
    loop {
        line.clear();
        let n = reader
            .read_line(&mut line)
            .await
            .map_err(|e| format!("SMTP read failed: {}", e))?;
        if n == 0 {
            return Err("SMTP connection closed unexpectedly".to_string());
        }
        let bytes = line.as_bytes();
        if bytes.len() < 4 {
            return Err(format!("Malformed SMTP response: {}", line.trim()));
        }
        let code: u16 = line[..3]
            .parse()
            .map_err(|_| format!("Invalid SMTP code: {}", line.trim()))?;
        let sep = bytes[3];
        if sep == b'-' {
            continue;
        }
        if code != expected_code {
            return Err(format!(
                "SMTP expected {} got {}",
                expected_code,
                line.trim()
            ));
        }
        return Ok(());
    }
}

fn dot_stuff_body(body: &str) -> String {
    body.replace("\r\n", "\n")
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
    s.replace(['\r', '\n'], " ")
}
