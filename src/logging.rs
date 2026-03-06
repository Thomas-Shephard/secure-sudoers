//! Structured logging initialisation for secure-sudoers.
//!
//! Reads `log_destination` and `log_format` from `GlobalSettings` and
//! configures the global `tracing` subscriber accordingly.
//!
//! | destination | format | result                                         |
//! |-------------|--------|------------------------------------------------|
//! | `stdout`    | `text` | `tracing-subscriber` fmt (human-readable)      |
//! | `stdout`    | `json` | `tracing-subscriber` fmt JSON                  |
//! | `syslog`    | any    | Custom [`SyslogLayer`] → `/dev/log` (Linux)    |
//! | `syslog`    | any    | Falls back to stdout on non-Linux platforms    |

use crate::models::GlobalSettings;

/// Configure the global tracing subscriber from policy settings.
///
/// Must be called exactly once, after the policy has been loaded.
/// Panics if called a second time (tracing subscriber already set).
pub fn init_logging(settings: &GlobalSettings) {
    match settings.log_destination.as_str() {
        "syslog" => init_syslog(settings),
        _ => init_stdout(settings),
    }
}

// ── stdout paths ──────────────────────────────────────────────────────────────

fn init_stdout(settings: &GlobalSettings) {
    if settings.log_format == "json" {
        tracing_subscriber::fmt()
            .with_writer(std::io::stdout)
            .json()
            .init();
    } else {
        tracing_subscriber::fmt()
            .with_writer(std::io::stdout)
            .init();
    }
}

// ── syslog path (Linux only) ──────────────────────────────────────────────────

#[cfg(target_os = "linux")]
fn init_syslog(settings: &GlobalSettings) {
    use syslog::{Facility, Formatter3164};
    use tracing_subscriber::prelude::*;

    let formatter = Formatter3164 {
        facility: Facility::LOG_AUTHPRIV,
        hostname: None,
        process: "secure-sudoers".into(),
        pid: std::process::id(),
    };

    match syslog::unix(formatter) {
        Ok(writer) => {
            tracing_subscriber::registry()
                .with(SyslogLayer::new(writer))
                .init();
        }
        Err(e) => {
            // Syslog socket unavailable (e.g. inside a container without
            // /dev/log).  Fall back to stderr so audit events are never lost.
            eprintln!(
                "secure-sudoers: WARNING: syslog unavailable ({}); \
                 falling back to stderr logging",
                e
            );
            init_stdout(settings);
        }
    }
}

#[cfg(not(target_os = "linux"))]
fn init_syslog(settings: &GlobalSettings) {
    // syslog is a POSIX/Linux concept; fall back to stdout on other platforms.
    init_stdout(settings);
}

// ── Custom tracing Layer that forwards events to the syslog socket ────────────

#[cfg(target_os = "linux")]
struct SyslogLayer {
    writer: std::sync::Mutex<syslog::Logger<syslog::LoggerBackend, syslog::Formatter3164>>,
}

#[cfg(target_os = "linux")]
impl SyslogLayer {
    fn new(writer: syslog::Logger<syslog::LoggerBackend, syslog::Formatter3164>) -> Self {
        Self {
            writer: std::sync::Mutex::new(writer),
        }
    }
}

#[cfg(target_os = "linux")]
impl<S: tracing::Subscriber> tracing_subscriber::Layer<S> for SyslogLayer {
    fn on_event(
        &self,
        event: &tracing::Event<'_>,
        _ctx: tracing_subscriber::layer::Context<'_, S>,
    ) {
        let mut visitor = MessageVisitor::default();
        event.record(&mut visitor);
        let msg = visitor.finish();

        if let Ok(mut w) = self.writer.lock() {
            // Ignore write errors — syslog failure must not abort the tool.
            let _ = match *event.metadata().level() {
                tracing::Level::ERROR => w.err(msg.as_str()),
                tracing::Level::WARN => w.warning(msg.as_str()),
                tracing::Level::INFO => w.info(msg.as_str()),
                _ => w.debug(msg.as_str()),
            };
        }
    }
}

// ── Field visitor: formats a tracing Event into a flat log string ─────────────

#[cfg(target_os = "linux")]
#[derive(Default)]
struct MessageVisitor {
    message: String,
    fields: String,
}

#[cfg(target_os = "linux")]
impl MessageVisitor {
    fn finish(self) -> String {
        if self.fields.is_empty() {
            self.message
        } else {
            format!("{} |{}", self.message, self.fields)
        }
    }
}

#[cfg(target_os = "linux")]
impl tracing::field::Visit for MessageVisitor {
    fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
        let sanitized = value.replace('\n', "\\n").replace('\r', "\\r");
        if field.name() == "message" {
            self.message = sanitized;
        } else {
            self.fields.push_str(&format!(" {}={}", field.name(), sanitized));
        }
    }

    fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
        let val_str = format!("{:?}", value);
        let sanitized = val_str.replace('\n', "\\n").replace('\r', "\\r");
        if field.name() == "message" {
            self.message = sanitized;
        } else {
            self.fields.push_str(&format!(" {}={}", field.name(), sanitized));
        }
    }
}
