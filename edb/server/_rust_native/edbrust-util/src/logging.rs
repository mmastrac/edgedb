use pyo3::prelude::*;
use pyo3::{types::PyAnyMethods, Py, PyAny, PyResult, Python};
use scopeguard::defer;
use std::cell::RefCell;
use std::collections::HashMap;
use std::sync::Mutex;
use std::sync::OnceLock;
use tracing::subscriber::DefaultGuard;
use tracing::Dispatch;
use tracing_subscriber::filter::LevelFilter;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::prelude::*;

static EDGEDB_RUST_PYTHON_LOGGER_DEBUG: OnceLock<bool> = OnceLock::new();
static LOGGER: OnceLock<Mutex<LoggerBridge>> = OnceLock::new();

fn is_debug_enabled() -> bool {
    *EDGEDB_RUST_PYTHON_LOGGER_DEBUG.get_or_init(|| {
        std::env::var("EDGEDB_RUST_PYTHON_LOGGER_DEBUG")
            .map(|v| v == "1")
            .unwrap_or(false)
    })
}

/// A useful tool for debugging logging.
#[macro_export]
macro_rules! debug_log_method {
    ($method_name:expr, $($arg:tt)*) => {
        if is_debug_enabled() {
            debug_log!($($arg)*);
            defer! {
                debug_log!("{} exited", $method_name);
            }
        }
    };
}

/// A simple debug logging macro that prints to stderr if debug logging is enabled.
#[macro_export]
macro_rules! debug_log {
    ($($arg:tt)*) => {
        if is_debug_enabled() {
            eprint!("LOGGING [{}]: ", std::process::id());
            eprintln!($($arg)*);
        }
    };
}

/// Provides a logger for the given Rust package and Python logger. Initializes
/// the logger if it is not already initialized.
///
/// This is the public interface for the Python/Rust logging integration system.
pub fn get_logger(py: Python, rust_package: &str, python_logger: &str) -> PyResult<LoggingGuard> {
    debug_log_method!(
        "get_logger",
        "get_logger called with rust_package: {}, python_logger: {}",
        rust_package,
        python_logger
    );
    LoggingGuard::new(rust_package.to_string(), python_logger.to_string(), py)
}

/// Initializes logging for the current thread. This function should be called
/// at the start of any new thread that needs to use logging.
///
/// Important: logging from threads requires taking the GIL and may have
/// performance impacts.
pub fn initialize_logging_in_thread() {
    debug_log_method!(
        "initialize_logging_in_thread",
        "Initializing logging in thread"
    );
    with_logger(|logger_bridge| {
        thread_local! {
            static GUARD: RefCell<Option<DefaultGuard>> = RefCell::new(None);
        }
        GUARD.with(|g| {
            let dispatch = &logger_bridge
                .dispatch
                .as_ref()
                .expect("LoggerBridge dispatch is not initialized")
                .clone();
            *g.borrow_mut() = Some(tracing::dispatcher::set_default(dispatch));
        });
    });
}

fn with_logger<F, R>(f: F) -> R
where
    F: FnOnce(&mut LoggerBridge) -> R,
{
    LOGGER.get_or_init(|| Mutex::new(LoggerBridge::default()));
    let mut guard = LOGGER.get().unwrap().lock().unwrap();
    f(&mut guard)
}

fn python_to_rust_level(level: i32) -> LevelFilter {
    match level {
        ..10 => LevelFilter::TRACE,
        10 => LevelFilter::DEBUG,
        11..=20 => LevelFilter::INFO,
        21..=30 => LevelFilter::WARN,
        31..=40 => LevelFilter::ERROR,
        _ => LevelFilter::OFF,
    }
}

fn log(py: Python, logger: &Py<PyAny>, event: &tracing::Event) {
    debug_log_method!("log", "log function called");
    let mut message = format!("[{}] ", event.metadata().target());
    #[derive(Default)]
    struct Visitor(String);
    impl tracing::field::Visit for Visitor {
        fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
            if field.name() == "message" {
                self.0 += &format!("{value:?} ");
            } else {
                self.0 += &format!("{}={:?} ", field.name(), value)
            }
        }
    }

    let mut visitor = Visitor::default();
    event.record(&mut visitor);
    message += &visitor.0;

    let log_method = match *event.metadata().level() {
        tracing::Level::TRACE | tracing::Level::DEBUG => "debug",
        tracing::Level::INFO => "info",
        tracing::Level::WARN => "warning",
        tracing::Level::ERROR => "error",
    };

    if let Ok(log) = logger.getattr(py, log_method) {
        let _ = log.call1(py, (message,));
    }
}

struct LoggerInfo {
    python_logger: Py<PyAny>,
    level: LevelFilter,
}

impl LoggerInfo {
    fn clone_ref(&self, py: Python<'_>) -> Self {
        LoggerInfo {
            python_logger: self.python_logger.clone_ref(py),
            level: self.level,
        }
    }
}

#[derive(Default)]
struct LoggerBridge {
    loggers: HashMap<String, LoggerInfo>,
    dispatch: Option<Dispatch>,
    guard: Option<tracing::dispatcher::DefaultGuard>,
}

impl<S: tracing::Subscriber> tracing_subscriber::Layer<S> for LoggerBridge {
    fn on_event(
        &self,
        event: &tracing::Event<'_>,
        _ctx: tracing_subscriber::layer::Context<'_, S>,
    ) {
        debug_log_method!("on_event", "LoggerBridge on_event called");
        Python::with_gil(|py| {
            for (_, logger_info) in &self.loggers {
                log(py, &logger_info.python_logger, event);
            }
        });
    }
}

impl<S> tracing_subscriber::layer::Filter<S> for LoggerBridge {
    fn enabled(
        &self,
        metadata: &tracing::Metadata<'_>,
        _: &tracing_subscriber::layer::Context<'_, S>,
    ) -> bool {
        debug_log_method!(
            "enabled",
            "LoggerBridge enabled check for target: {} and level {:?}",
            metadata.target(),
            metadata.level()
        );
        let crate_name = metadata
            .target()
            .split("::")
            .next()
            .unwrap_or(metadata.target());
        let result = if let Some(info) = self.loggers.get(crate_name) {
            debug_log!("Testing against level: {:?}", info.level);
            metadata.level() <= &info.level
        } else {
            debug_log!("No logger found for crate: {}", crate_name);
            false
        };
        result
    }
}

impl LoggerBridge {
    fn clone_ref(&self, py: Python<'_>) -> Self {
        LoggerBridge {
            loggers: self
                .loggers
                .iter()
                .map(|(k, v)| (k.clone(), v.clone_ref(py)))
                .collect(),
            dispatch: self.dispatch.clone(),
            guard: None,
        }
    }

    fn add_logger(
        &mut self,
        rust_package: String,
        python_logger: String,
        py: Python,
    ) -> PyResult<()> {
        debug_log_method!(
            "add_logger",
            "LoggerBridge add_logger called for rust_package: {}, python_logger: {}",
            rust_package,
            python_logger
        );
        let logging = py.import_bound("logging")?;
        let logger = logging.getattr("getLogger")?.call1((python_logger,))?;
        let level = logger
            .getattr("getEffectiveLevel")?
            .call0()?
            .extract::<i32>()?;
        let level_filter = python_to_rust_level(level);
        debug_log!(
            "Logger level updated - Python level: {}, Rust level: {:?}",
            level,
            level_filter
        );
        self.loggers.insert(
            rust_package,
            LoggerInfo {
                python_logger: logger.into(),
                level: level_filter,
            },
        );
        Ok(())
    }

    fn remove_logger(&mut self, rust_package: &str) {
        debug_log_method!(
            "remove_logger",
            "LoggerBridge remove_logger called for rust_package: {}",
            rust_package
        );
        self.loggers.remove(rust_package);
    }

    fn update_subscriber(&mut self, py: Python) -> PyResult<()> {
        debug_log_method!("update_subscriber", "LoggerBridge update_subscriber called");
        let subscriber =
            tracing_subscriber::registry().with(self.clone_ref(py).with_filter(self.clone_ref(py)));
        let dispatch = Dispatch::new(subscriber);
        self.dispatch = Some(dispatch.clone());
        self.guard.take();
        self.guard = Some(tracing::dispatcher::set_default(&dispatch));
        Ok(())
    }

    fn refresh(&mut self, py: Python) -> PyResult<()> {
        debug_log_method!("refresh", "LoggerBridge refresh called");
        for (_, logger_info) in &mut self.loggers {
            let logger = logger_info.python_logger.clone_ref(py);
            let level = logger
                .getattr(py, "getEffectiveLevel")?
                .call0(py)?
                .extract::<i32>(py)?;
            let level_filter = python_to_rust_level(level);
            debug_log!(
                "Logger level updated - Python level: {}, Rust level: {:?}",
                level,
                level_filter
            );
            logger_info.level = level_filter;
        }
        self.update_subscriber(py)
    }
}

#[pyclass]
pub struct LoggingGuard {
    rust_package: String,
}

impl Drop for LoggingGuard {
    fn drop(&mut self) {
        debug_log_method!(
            "drop",
            "LoggingGuard drop called for rust_package: {}",
            self.rust_package
        );
        let _ = Python::with_gil(|py| {
            with_logger(|logger| {
                logger.remove_logger(&self.rust_package);
                logger.update_subscriber(py)
            })
        });
    }
}

impl LoggingGuard {
    fn new(rust_package: String, python_logger: String, py: Python) -> PyResult<Self> {
        debug_log_method!(
            "new",
            "LoggingGuard new called for rust_package: {}, python_logger: {}",
            rust_package,
            python_logger
        );
        let result = with_logger(|logger| {
            logger.add_logger(rust_package.clone(), python_logger, py)?;
            logger.update_subscriber(py)?;
            Ok(LoggingGuard { rust_package })
        });
        result
    }
}

#[pymethods]
impl LoggingGuard {
    pub fn refresh(&self) -> PyResult<()> {
        debug_log_method!("refresh", "LoggingGuard refresh called");
        let result = Python::with_gil(|py| with_logger(|logger| logger.refresh(py)));
        result
    }
}
