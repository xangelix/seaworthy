//! A minimal `tracing` subscriber writing one line per event, shared by the
//! lab's service (`scm_core`) and its update helper (`scm_helper`, through
//! `#[path]`): the fixture keeps its dependency set small, and
//! tracing-subscriber is not part of it. Under the Service Control Manager
//! a process has no console, so the lines go to files the lane scripts
//! read.
//!
//! ```text
//! <unix ms> <LEVEL> <target>: <message> <field>=<value>...
//! ```

use std::{
    fmt,
    io::Write,
    sync::{
        Mutex, PoisonError,
        atomic::{AtomicU64, Ordering},
    },
    time::{SystemTime, UNIX_EPOCH},
};

/// Milliseconds since the Unix epoch (0 before it).
pub(crate) fn unix_ms() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_millis())
}

/// `text` on one line: control characters (C0, DEL, C1), the Unicode line
/// and paragraph separators and the bidirectional overrides escaped as
/// `\u{..}`, so a value read from a file or the network can neither break a
/// log line in two nor reorder what a reader sees.
pub(crate) fn line_safe(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        let hidden = c.is_control()
            || matches!(
                c,
                '\u{2028}' | '\u{2029}' | '\u{200e}' | '\u{200f}' | '\u{202a}'..='\u{202e}'
                    | '\u{2066}'..='\u{2069}'
            );
        if hidden {
            out.push_str(&format!("\\u{{{:x}}}", u32::from(c)));
        } else {
            out.push(c);
        }
    }
    out
}

/// Installs the process's subscriber: every event at INFO or above, one
/// line each, to every writer in `outputs` (flushed per line). A second
/// call keeps the first subscriber.
pub(crate) fn install(outputs: Vec<Box<dyn Write + Send>>) {
    let _ = tracing::subscriber::set_global_default(LineSubscriber {
        outputs: Mutex::new(outputs),
        next_span: AtomicU64::new(0),
    });
}

struct LineSubscriber {
    outputs: Mutex<Vec<Box<dyn Write + Send>>>,
    next_span: AtomicU64,
}

#[derive(Default)]
struct LineVisitor {
    message: String,
    fields: String,
}

impl tracing::field::Visit for LineVisitor {
    fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn fmt::Debug) {
        if field.name() == "message" {
            self.message = format!("{value:?}");
        } else {
            self.fields
                .push_str(&format!(" {}={value:?}", field.name()));
        }
    }

    fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
        if field.name() == "message" {
            self.message = value.to_owned();
        } else {
            self.fields.push_str(&format!(" {}={value}", field.name()));
        }
    }
}

impl tracing::Subscriber for LineSubscriber {
    fn enabled(&self, metadata: &tracing::Metadata<'_>) -> bool {
        // tracing orders levels by verbosity: INFO and more severe pass.
        *metadata.level() <= tracing::Level::INFO
    }

    fn new_span(&self, _span: &tracing::span::Attributes<'_>) -> tracing::span::Id {
        tracing::span::Id::from_u64(self.next_span.fetch_add(1, Ordering::Relaxed) + 1)
    }

    fn record(&self, _span: &tracing::span::Id, _values: &tracing::span::Record<'_>) {}

    fn record_follows_from(&self, _span: &tracing::span::Id, _follows: &tracing::span::Id) {}

    fn event(&self, event: &tracing::Event<'_>) {
        let mut visitor = LineVisitor::default();
        event.record(&mut visitor);
        let metadata = event.metadata();
        let line = line_safe(&format!(
            "{} {} {}: {}{}",
            unix_ms(),
            metadata.level(),
            metadata.target(),
            visitor.message,
            visitor.fields
        ));
        let mut outputs = self.outputs.lock().unwrap_or_else(PoisonError::into_inner);
        for out in outputs.iter_mut() {
            let _ = writeln!(out, "{line}");
            let _ = out.flush();
        }
    }

    fn enter(&self, _span: &tracing::span::Id) {}

    fn exit(&self, _span: &tracing::span::Id) {}
}
