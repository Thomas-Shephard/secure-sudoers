use crate::models::GlobalSettings;
use syslog::{Facility, Formatter3164};
use tracing_subscriber::prelude::*;
use tracing_subscriber::util::SubscriberInitExt;

pub fn init_logging(settings: &GlobalSettings) {
    match settings.log_destination.as_str() {
        "syslog" => init_syslog(settings),
        _ => init_stdout(settings),
    }
}

fn init_stdout(settings: &GlobalSettings) {
    let builder = tracing_subscriber::fmt().with_writer(std::io::stdout);
    let _ = if settings.log_format == "json" { builder.json().try_init() } else { builder.try_init() };
}

fn init_syslog(settings: &GlobalSettings) {
    let formatter = Formatter3164 {
        facility: Facility::LOG_AUTHPRIV,
        hostname: None,
        process: "secure-sudoers".into(),
        pid: std::process::id(),
    };

    match syslog::unix(formatter) {
        Ok(writer) => {
            let _ = tracing_subscriber::registry().with(SyslogLayer::new(writer)).try_init();
        }
        Err(e) => {
            eprintln!("secure-sudoers: syslog unavailable ({}); falling back to stdout", e);
            init_stdout(settings);
        }
    }
}

struct SyslogLayer {
    writer: std::sync::Mutex<syslog::Logger<syslog::LoggerBackend, Formatter3164>>,
}

impl SyslogLayer {
    fn new(writer: syslog::Logger<syslog::LoggerBackend, Formatter3164>) -> Self {
        Self { writer: std::sync::Mutex::new(writer) }
    }
}

impl<S: tracing::Subscriber> tracing_subscriber::Layer<S> for SyslogLayer {
    fn on_event(&self, event: &tracing::Event<'_>, _ctx: tracing_subscriber::layer::Context<'_, S>) {
        let mut visitor = MessageVisitor::default();
        event.record(&mut visitor);
        let msg = visitor.finish();
        if let Ok(mut w) = self.writer.lock() {
            let _ = match *event.metadata().level() {
                tracing::Level::ERROR => w.err(&msg),
                tracing::Level::WARN => w.warning(&msg),
                tracing::Level::INFO => w.info(&msg),
                _ => w.debug(&msg),
            };
        }
    }
}

#[derive(Default)]
struct MessageVisitor {
    message: String,
    fields: String,
}

impl MessageVisitor {
    fn finish(self) -> String {
        if self.fields.is_empty() { self.message } else { format!("{} |{}", self.message, self.fields) }
    }

    fn record_value(&mut self, field: &tracing::field::Field, value: String) {
        let s = value.replace('\n', "\\n").replace('\r', "\\r");
        if field.name() == "message" {
            self.message = s;
        } else {
            self.fields.push_str(&format!(" {}={}", field.name(), s));
        }
    }
}

impl tracing::field::Visit for MessageVisitor {
    fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
        self.record_value(field, value.to_string());
    }
    fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
        self.record_value(field, format!("{:?}", value));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{GlobalSettings, UnauthorizedAuditMode};
    use std::sync::{Arc, Mutex};
    use tracing_subscriber::layer::SubscriberExt;

    /// Installs a temporary per-call tracing subscriber and returns all formatted
    /// `MessageVisitor::finish()` strings emitted inside the closure.
    fn capture_events<F: FnOnce()>(f: F) -> Vec<String> {
        struct Capturer(Arc<Mutex<Vec<String>>>);
        impl<S: tracing::Subscriber> tracing_subscriber::Layer<S> for Capturer {
            fn on_event(
                &self,
                event: &tracing::Event<'_>,
                _ctx: tracing_subscriber::layer::Context<'_, S>,
            ) {
                let mut v = MessageVisitor::default();
                event.record(&mut v);
                self.0.lock().unwrap().push(v.finish());
            }
        }
        let store = Arc::new(Mutex::new(Vec::new()));
        let sub = tracing_subscriber::registry().with(Capturer(Arc::clone(&store)));
        tracing::subscriber::with_default(sub, f);
        Arc::try_unwrap(store).unwrap().into_inner().unwrap()
    }

    fn stdout_settings(json: bool) -> GlobalSettings {
        GlobalSettings {
            log_destination: "stdout".to_string(),
            log_format: if json { "json".to_string() } else { "text".to_string() },
            admin_contact: "admin@example.com".to_string(),
            safe_arg_regex: r"^[a-zA-Z0-9._+\-=:,@/]+$".to_string(),
            common_env_whitelist: vec![],
            dry_run: false,
            blocked_paths: vec![],
            bypass_groups: vec![],
            unauthorized_audit_mode: UnauthorizedAuditMode::Minimal,
            default_isolation: None,
        }
    }

    #[test]
    fn test_message_only_finish() {
        let msgs = capture_events(|| tracing::info!("hello world"));
        assert_eq!(msgs[0], "hello world");
    }

    #[test]
    fn test_fields_appended_after_pipe() {
        let msgs = capture_events(|| tracing::info!(tool = "apt", user = "alice", "approved"));
        let m = &msgs[0];
        assert!(m.starts_with("approved"), "message first: {m}");
        assert!(m.contains(" |"), "pipe separator: {m}");
        assert!(m.contains("tool=apt"), "tool field: {m}");
        assert!(m.contains("user=alice"), "user field: {m}");
    }

    #[test]
    fn test_message_newline_escaped() {
        let msgs = capture_events(|| tracing::info!("line1\nline2"));
        assert_eq!(msgs[0], "line1\\nline2");
    }

    #[test]
    fn test_message_carriage_return_escaped() {
        let msgs = capture_events(|| tracing::info!("line1\rline2"));
        assert_eq!(msgs[0], "line1\\rline2");
    }

    #[test]
    fn test_field_value_newline_escaped() {
        let msgs = capture_events(|| tracing::info!(note = "a\nb", "msg"));
        assert!(msgs[0].contains("a\\nb"), "field newline: {}", msgs[0]);
    }

    #[test]
    fn test_debug_field_via_record_debug() {
        let msgs = capture_events(|| {
            let args: Vec<&str> = vec!["--flag", "[REDACTED]"];
            tracing::info!(args = ?args, "debug field");
        });
        assert!(msgs[0].contains("--flag"), "{}", msgs[0]);
        assert!(msgs[0].contains("[REDACTED]"), "{}", msgs[0]);
    }

    #[test]
    fn test_empty_fields_yields_message_only() {
        // When no extra fields are recorded, finish() returns just the message.
        let v = MessageVisitor::default();
        // fields is empty by default – call finish without recording anything
        assert_eq!(v.finish(), "");
    }

    #[test]
    fn test_init_logging_stdout_text_does_not_panic() {
        // try_init() silently fails if a global subscriber is already set; must not panic.
        init_logging(&stdout_settings(false));
    }

    #[test]
    fn test_init_logging_stdout_json_does_not_panic() {
        init_logging(&stdout_settings(true));
    }

    #[test]
    fn test_init_logging_syslog_falls_back_gracefully() {
        // Without /dev/log (typical in unit-test env), syslog::unix() fails and we
        // fall back to init_stdout – which uses try_init() so it never panics.
        let settings = GlobalSettings {
            log_destination: "syslog".to_string(),
            ..stdout_settings(false)
        };
        init_logging(&settings);
    }
}
