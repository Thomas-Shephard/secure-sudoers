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

pub fn init_logging_fallback() {
    let _ = tracing_subscriber::fmt()
        .with_writer(std::io::stdout)
        .try_init();
}

fn init_stdout(settings: &GlobalSettings) {
    let builder = tracing_subscriber::fmt().with_writer(std::io::stdout);
    let _ = if settings.log_format == "json" {
        builder.json().try_init()
    } else {
        builder.try_init()
    };
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
            let _ = tracing_subscriber::registry()
                .with(SyslogLayer::new(writer))
                .try_init();
        }
        Err(e) => {
            eprintln!(
                "secure-sudoers: syslog unavailable ({}); falling back to stdout",
                e
            );
            init_stdout(settings);
        }
    }
}

struct SyslogLayer {
    writer: std::sync::Mutex<syslog::Logger<syslog::LoggerBackend, Formatter3164>>,
}

impl SyslogLayer {
    fn new(writer: syslog::Logger<syslog::LoggerBackend, Formatter3164>) -> Self {
        Self {
            writer: std::sync::Mutex::new(writer),
        }
    }
}

impl<S: tracing::Subscriber> tracing_subscriber::Layer<S> for SyslogLayer {
    fn on_event(
        &self,
        event: &tracing::Event<'_>,
        _ctx: tracing_subscriber::layer::Context<'_, S>,
    ) {
        let mut visitor = JsonVisitor::default();
        event.record(&mut visitor);
        let msg = visitor.finish(*event.metadata().level());

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
struct JsonVisitor {
    security_event_json: Option<String>,
    fields: serde_json::Map<String, serde_json::Value>,
    message: Option<String>,
}

impl JsonVisitor {
    fn finish(mut self, level: tracing::Level) -> String {
        if let Some(json) = self.security_event_json {
            return json;
        }
        if let Some(msg) = self.message.take() {
            self.fields
                .insert("message".to_string(), serde_json::Value::String(msg));
        }
        self.fields.insert(
            "level".to_string(),
            serde_json::Value::String(level.to_string()),
        );
        serde_json::to_string(&self.fields)
            .unwrap_or_else(|e| format!("{{\"error\":\"json serialization failed: {}\"}}", e))
    }

    fn record_value(&mut self, field: &tracing::field::Field, value: serde_json::Value) {
        let name = field.name();
        if name == "security_event_json" {
            let json_str = match value {
                serde_json::Value::String(s) => s,
                other => serde_json::to_string(&other).unwrap_or_else(|_| "{}".to_string()),
            };
            self.security_event_json = Some(json_str);
        } else if name == "message" {
            if let serde_json::Value::String(s) = value {
                self.message = Some(s);
            }
        } else {
            self.fields.insert(name.to_string(), value);
        }
    }
}

impl tracing::field::Visit for JsonVisitor {
    fn record_f64(&mut self, field: &tracing::field::Field, value: f64) {
        let num =
            serde_json::Number::from_f64(value).unwrap_or_else(|| serde_json::Number::from(0));
        self.record_value(field, serde_json::Value::Number(num));
    }

    fn record_i64(&mut self, field: &tracing::field::Field, value: i64) {
        self.record_value(
            field,
            serde_json::Value::Number(serde_json::Number::from(value)),
        );
    }

    fn record_u64(&mut self, field: &tracing::field::Field, value: u64) {
        self.record_value(
            field,
            serde_json::Value::Number(serde_json::Number::from(value)),
        );
    }

    fn record_bool(&mut self, field: &tracing::field::Field, value: bool) {
        self.record_value(field, serde_json::Value::Bool(value));
    }

    fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
        self.record_value(field, serde_json::Value::String(value.to_string()));
    }

    fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
        let s = format!("{:?}", value);
        let json_val = serde_json::from_str::<serde_json::Value>(&s)
            .unwrap_or_else(|_| serde_json::Value::String(s));
        self.record_value(field, json_val);
    }
}

#[cfg(test)]
#[derive(Default)]
struct MessageVisitor {
    message: String,
    fields: String,
}

#[cfg(test)]
impl MessageVisitor {
    fn finish(self) -> String {
        if self.fields.is_empty() {
            self.message
        } else {
            format!("{} |{}", self.message, self.fields)
        }
    }

    fn record_value(&mut self, field: &tracing::field::Field, value: String) {
        let s = value.replace('\n', "\\n").replace('\r', "\\r");
        if field.name() == "message" {
            self.message = s;
        } else {
            let s_escaped = s.replace('"', "\\\"");
            self.fields
                .push_str(&format!(" {}=\"{}\"", field.name(), s_escaped));
        }
    }
}

#[cfg(test)]
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

    fn get_capturer() -> (Arc<Mutex<Vec<String>>>, impl tracing::Subscriber) {
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
        (store, sub)
    }

    fn get_json_capturer() -> (Arc<Mutex<Vec<String>>>, impl tracing::Subscriber) {
        struct JsonCapturer(Arc<Mutex<Vec<String>>>);
        impl<S: tracing::Subscriber> tracing_subscriber::Layer<S> for JsonCapturer {
            fn on_event(
                &self,
                event: &tracing::Event<'_>,
                _ctx: tracing_subscriber::layer::Context<'_, S>,
            ) {
                let mut v = JsonVisitor::default();
                event.record(&mut v);
                self.0
                    .lock()
                    .unwrap()
                    .push(v.finish(*event.metadata().level()));
            }
        }
        let store = Arc::new(Mutex::new(Vec::new()));
        let sub = tracing_subscriber::registry().with(JsonCapturer(Arc::clone(&store)));
        (store, sub)
    }

    fn stdout_settings(json: bool) -> GlobalSettings {
        GlobalSettings {
            log_destination: "stdout".to_string(),
            log_format: if json {
                "json".to_string()
            } else {
                "text".to_string()
            },
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
        let (store, sub) = get_capturer();
        tracing::subscriber::with_default(sub, || {
            tracing::info!("hello world");
        });
        let msgs = Arc::try_unwrap(store).unwrap().into_inner().unwrap();
        assert_eq!(msgs[0], "hello world");
    }

    #[test]
    fn test_fields_appended_after_pipe() {
        let (store, sub) = get_capturer();
        tracing::subscriber::with_default(sub, || {
            tracing::info!(tool = "apt", user = "alice", "approved");
        });
        let msgs = Arc::try_unwrap(store).unwrap().into_inner().unwrap();
        let m = &msgs[0];
        assert!(m.starts_with("approved"), "message first: {m}");
        assert!(m.contains(" |"), "pipe separator: {m}");
        assert!(m.contains("tool=\"apt\""), "tool field: {m}");
        assert!(m.contains("user=\"alice\""), "user field: {m}");
    }

    #[test]
    fn test_message_newline_escaped() {
        let (store, sub) = get_capturer();
        tracing::subscriber::with_default(sub, || {
            tracing::info!("line1\nline2");
        });
        let msgs = Arc::try_unwrap(store).unwrap().into_inner().unwrap();
        assert_eq!(msgs[0], "line1\\nline2");
    }

    #[test]
    fn test_message_carriage_return_escaped() {
        let (store, sub) = get_capturer();
        tracing::subscriber::with_default(sub, || {
            tracing::info!("line1\rline2");
        });
        let msgs = Arc::try_unwrap(store).unwrap().into_inner().unwrap();
        assert_eq!(msgs[0], "line1\\rline2");
    }

    #[test]
    fn test_field_value_newline_escaped() {
        let (store, sub) = get_capturer();
        tracing::subscriber::with_default(sub, || {
            tracing::info!(note = "a\nb", "msg");
        });
        let msgs = Arc::try_unwrap(store).unwrap().into_inner().unwrap();
        assert!(msgs[0].contains("a\\nb"), "field newline: {}", msgs[0]);
    }

    #[test]
    fn test_debug_field_via_record_debug() {
        let (store, sub) = get_capturer();
        tracing::subscriber::with_default(sub, || {
            let args: Vec<&str> = vec!["--flag", "[REDACTED]"];
            tracing::info!(args = ?args, "debug field");
        });
        let msgs = Arc::try_unwrap(store).unwrap().into_inner().unwrap();
        assert!(msgs[0].contains("--flag"), "{}", msgs[0]);
        assert!(msgs[0].contains("[REDACTED]"), "{}", msgs[0]);
    }

    #[test]
    fn test_empty_fields_yields_message_only() {
        let v = MessageVisitor::default();
        assert_eq!(v.finish(), "");
    }

    #[test]
    fn test_init_logging_stdout_text_does_not_panic() {
        init_logging(&stdout_settings(false));
    }

    #[test]
    fn test_init_logging_stdout_json_does_not_panic() {
        init_logging(&stdout_settings(true));
    }

    #[test]
    fn test_init_logging_syslog_falls_back_gracefully() {
        let settings = GlobalSettings {
            log_destination: "syslog".to_string(),
            ..stdout_settings(false)
        };
        init_logging(&settings);
    }

    #[test]
    fn test_json_visitor_produces_valid_json() {
        let (store, sub) = get_json_capturer();
        tracing::subscriber::with_default(sub, || {
            tracing::info!(tool = "apt", user = "alice", "approved");
        });
        let msgs = Arc::try_unwrap(store).unwrap().into_inner().unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&msgs[0]).expect("must be valid JSON");
        assert_eq!(parsed["tool"], "apt");
        assert_eq!(parsed["user"], "alice");
        assert_eq!(parsed["message"], "approved");
        assert_eq!(parsed["level"], "INFO");
    }

    #[test]
    fn test_json_visitor_security_event_json_passthrough() {
        let event_json = r#"{"event_id":"SEC-403","txn_id":"abc12345"}"#;
        let (store, sub) = get_json_capturer();
        tracing::subscriber::with_default(sub, || {
            tracing::warn!(security_event_json = %event_json, "denied");
        });
        let msgs = Arc::try_unwrap(store).unwrap().into_inner().unwrap();
        assert_eq!(msgs[0], event_json);
    }

    #[test]
    fn test_json_visitor_u64_field() {
        let (store, sub) = get_json_capturer();
        tracing::subscriber::with_default(sub, || {
            tracing::info!(uid = 1000u64, "identity");
        });
        let msgs = Arc::try_unwrap(store).unwrap().into_inner().unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&msgs[0]).unwrap();
        assert_eq!(parsed["uid"], 1000);
    }

    #[test]
    fn test_json_visitor_bool_field() {
        let (store, sub) = get_json_capturer();
        tracing::subscriber::with_default(sub, || {
            tracing::info!(dry_run = true, "check");
        });
        let msgs = Arc::try_unwrap(store).unwrap().into_inner().unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&msgs[0]).unwrap();
        assert_eq!(parsed["dry_run"], true);
    }
}
