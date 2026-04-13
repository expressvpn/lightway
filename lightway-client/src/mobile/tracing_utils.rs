// The tracing log utils for bridging with mobiles
use std::fmt::Debug;

use tracing::{
    Subscriber,
    event::Event,
    field::{Field, Visit},
};
use tracing_core::Level;
use tracing_subscriber::{
    Registry,
    layer::{Context, Layer},
};

use std::sync::{Arc, OnceLock, RwLock};
use thiserror::Error;
use tracing_core::dispatcher::{DefaultGuard, SetGlobalDefaultError, has_been_set};
use tracing_core::span::{Attributes, Id};
use tracing_subscriber::registry::LookupSpan;

#[uniffi::export(with_foreign)]
pub trait Logger: Send + Sync {
    fn debug(&self, msg: String);
    fn info(&self, msg: String);
    fn warn(&self, msg: String);
    fn error(&self, msg: String);
}

/// Thin proxy that allows swapping the underlying mobile logger between VPN sessions while keeping
/// the same subscriber machinery registered with `tracing`. This is primarily needed on Android,
/// where the app hands us a fresh logger for every connection instead of spawning a new process.
/// All method calls delegate to the currently configured logger inside an `Arc`.
struct SwappableLogger {
    delegate: RwLock<Arc<dyn Logger>>,
}

impl SwappableLogger {
    fn new(logger: Arc<dyn Logger>) -> Self {
        Self {
            delegate: RwLock::new(logger),
        }
    }

    fn replace(&self, logger: Arc<dyn Logger>) {
        *self.delegate.write().expect("global logger lock poisoned") = logger;
    }

    fn with_logger<F>(&self, action: F)
    where
        F: FnOnce(&dyn Logger),
    {
        let logger = self.delegate.read().expect("global logger lock poisoned");
        action(&**logger);
    }
}

impl Logger for SwappableLogger {
    fn debug(&self, msg: String) {
        self.with_logger(|logger| logger.debug(msg));
    }

    fn info(&self, msg: String) {
        self.with_logger(|logger| logger.info(msg));
    }

    fn warn(&self, msg: String) {
        self.with_logger(|logger| logger.warn(msg));
    }

    fn error(&self, msg: String) {
        self.with_logger(|logger| logger.error(msg));
    }
}

static GLOBAL_LOGGER: OnceLock<Arc<SwappableLogger>> = OnceLock::new();

#[derive(Debug, Error)]
pub enum LoggingBridgeError {
    #[error("a global tracing subscriber has already been installed by another component")]
    ConflictingGlobalSubscriber,
    #[error(transparent)]
    SetGlobalDefault(#[from] SetGlobalDefaultError),
}

/// Installs, or updates, the global tracing subscriber while reusing the same subscriber via a swappable logger.
/// On iOS each VPN session runs in a fresh Network Extension process, so this executes only once per connection.
/// On Android the library stays in the main process across sessions, so we expect multiple calls and swap the delegate instead.
/// Returns a `LoggingBridgeError::ConflictingGlobalSubscriber` if another component has already installed its own global subscriber.
pub(crate) fn set_global_default_subscriber(
    logger_callback: Arc<dyn Logger>,
) -> Result<(), LoggingBridgeError> {
    if let Some(logger) = GLOBAL_LOGGER.get() {
        // We already own the global subscriber, so just update the delegate in place.
        logger.replace(logger_callback);
        return Ok(());
    }

    if has_been_set() {
        // Another component installed its own global subscriber; we can't safely override it.
        return Err(LoggingBridgeError::ConflictingGlobalSubscriber);
    }

    // First-time initialization: install our subscriber and stash the shared logger
    // so subsequent calls can swap the delegate without touching tracing's global state.
    let logger = Arc::new(SwappableLogger::new(logger_callback));
    tracing::subscriber::set_global_default(setup_logging_subscriber(logger.clone()))?;
    let _ = GLOBAL_LOGGER.set(logger);

    Ok(())
}

/// Set the default tracing subscriber until the returned default guard gets dropped
pub(crate) fn set_default_guard_subscriber(logger_callback: Arc<dyn Logger>) -> DefaultGuard {
    let subscriber = setup_logging_subscriber(logger_callback);
    tracing::subscriber::set_default(subscriber)
}

fn setup_logging_subscriber(logger_callback: Arc<dyn Logger>) -> impl Subscriber {
    let diagnostic_layer = DiagnosticLayer::new(logger_callback);

    #[cfg(android)]
    return tracing_android::layer("lightway_rust")
        .unwrap()
        .and_then(diagnostic_layer)
        .with_subscriber(Registry::default());
    #[cfg(not(android))]
    diagnostic_layer.with_subscriber(Registry::default())
}

pub struct DiagnosticLayer {
    logger_callback: Arc<dyn Logger>,
}

const IGNORED_SPANS: &[&str] = &["CleanupConnection"];

impl DiagnosticLayer {
    pub fn new(logger_callback: Arc<dyn Logger>) -> Self {
        Self { logger_callback }
    }
}

struct DiagnosticVisitor {
    pub log: String,
}

impl DiagnosticVisitor {
    fn new() -> Self {
        Self { log: String::new() }
    }

    fn take_trimmed_log(&self) -> String {
        self.log.trim_end_matches(", ").to_string()
    }
}

impl Visit for DiagnosticVisitor {
    fn record_debug(&mut self, field: &Field, value: &dyn Debug) {
        let log_line = format!("{field}: {value:?}, ");
        self.log.push_str(log_line.as_str());
    }
}

impl<S> Layer<S> for DiagnosticLayer
where
    S: Subscriber + for<'a> LookupSpan<'a>,
{
    fn on_new_span(&self, attrs: &Attributes<'_>, id: &Id, ctx: Context<'_, S>) {
        let span = ctx.span(id).unwrap();
        let mut visitor = DiagnosticVisitor::new();
        attrs.record(&mut visitor);
        span.extensions_mut().insert(visitor.take_trimmed_log());
    }
    fn on_event(&self, event: &Event, ctx: Context<S>) {
        let event_level = event.metadata().level();
        let event_span = ctx.event_span(event);
        let prefix = match event_span {
            Some(span) if !span.name().is_empty() => {
                let span_name = span.name();
                if IGNORED_SPANS.contains(&span_name) && *event_level != Level::ERROR {
                    return;
                }
                let span_extensions = span.extensions();
                let span_values = span_extensions.get::<String>().map_or("", |v| v);
                format!("({}{{{}}}): ", span_name, span_values)
            }
            _ => "".to_string(),
        };

        let mut diagnostic_visitor = DiagnosticVisitor::new();
        event.record(&mut diagnostic_visitor);
        let log_message = format!("{}{}", prefix, diagnostic_visitor.take_trimmed_log());
        match *event_level {
            Level::INFO => self.logger_callback.info(log_message),
            Level::DEBUG | Level::TRACE => self.logger_callback.debug(log_message),
            Level::WARN => self.logger_callback.warn(log_message),
            Level::ERROR => self.logger_callback.error(log_message),
        }
    }
}
