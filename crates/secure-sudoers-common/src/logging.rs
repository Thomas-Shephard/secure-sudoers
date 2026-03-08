use crate::models::GlobalSettings;
use syslog::{Facility, Formatter3164};
use tracing_subscriber::prelude::*;

pub fn init_logging(settings: &GlobalSettings) {
    match settings.log_destination.as_str() {
        "syslog" => init_syslog(settings),
        _ => init_stdout(settings),
    }
}

fn init_stdout(settings: &GlobalSettings) {
    let builder = tracing_subscriber::fmt().with_writer(std::io::stdout);
    if settings.log_format == "json" { builder.json().init(); } else { builder.init(); }
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
            tracing_subscriber::registry().with(SyslogLayer::new(writer)).init();
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
