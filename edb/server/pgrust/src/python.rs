use crate::connection::state_machine::{
    ConnectionDrive, ConnectionState, ConnectionStateSend, ConnectionStateUpdate,
};
use crate::connection::ConnectionError;
use crate::protocol::{meta, StructBuffer};
use crate::{
    connection::{
        dsn::{parse_postgres_dsn_env, EnvVar},
        params::{HostType, Ssl},
        state_machine::ConnectionStateType,
        ConnectionSslRequirement, Credentials,
    },
    protocol::SSLResponse,
};
use pyo3::exceptions::PyRuntimeError;
use pyo3::types::PyBytes;
use pyo3::{
    buffer::PyBuffer,
    prelude::*,
    types::{PyMemoryView, PyNone},
};
use pyo3::{
    exceptions::PyException,
    pyfunction, pymodule,
    types::{PyAnyMethods, PyByteArray, PyModule, PyModuleMethods},
    wrap_pyfunction, Bound, PyAny, PyResult, Python,
};
use serde_pickle::SerOptions;
use std::path::Path;

impl From<ConnectionError> for PyErr {
    fn from(err: ConnectionError) -> PyErr {
        PyRuntimeError::new_err(err.to_string())
    }
}

impl EnvVar for (String, Bound<'_, PyAny>) {
    fn read(&self, name: &'static str) -> Option<std::borrow::Cow<str>> {
        // os.environ[name], or the default user if not
        let py_str = self.1.get_item(name).ok();
        if name == "PGUSER" && py_str.is_none() {
            Some((&self.0).into())
        } else {
            py_str.map(|s| s.to_string().into())
        }
    }
}

#[pyfunction]
fn parse_dsn(py: Python, username: String, home_dir: String, s: String) -> PyResult<Bound<PyAny>> {
    let pickle = py.import_bound("pickle")?;
    let loads = pickle.getattr("loads")?;
    let os = py.import_bound("os")?;
    let environ = os.getattr("environ")?;
    match parse_postgres_dsn_env(&s, (username, environ)) {
        Ok(mut res) => {
            if let Some(warning) =
                res.password
                    .resolve(Path::new(&home_dir), &res.hosts, &res.database, &res.user)?
            {
                let warnings = py.import_bound("warnings")?;
                warnings.call_method1("warn", (warning.to_string(),))?;
            }
            res.ssl.resolve(Path::new(&home_dir))?;
            // Use serde_pickle to get a python-compatible representation of the result
            let vec = serde_pickle::to_vec(&res, SerOptions::new()).unwrap();
            loads.call1((PyByteArray::new_bound(py, &vec),))
        }
        Err(err) => Err(PyException::new_err(err.to_string())),
    }
}

#[pymodule]
pub fn _pg_rust(_py: Python, m: &Bound<PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(parse_dsn, m)?)?;
    m.add_class::<PyConnectionState>()?;
    Ok(())
}

#[pyclass]
struct PyConnectionState {
    inner: ConnectionState,
    parsed_dsn: crate::connection::params::ConnectionParameters,
    update: PyConnectionStateUpdate,
    message_buffer: StructBuffer<meta::Message>,
}

#[pymethods]
impl PyConnectionState {
    #[new]
    fn new(py: Python, dsn: String, username: String, home_dir: String) -> PyResult<Self> {
        let os = py.import_bound("os")?;
        let environ = os.getattr("environ")?;
        match parse_postgres_dsn_env(&dsn, (username.clone(), environ)) {
            Ok(mut res) => {
                if let Some(warning) = res.password.resolve(
                    Path::new(&home_dir),
                    &res.hosts,
                    &res.database,
                    &res.user,
                )? {
                    let warnings = py.import_bound("warnings")?;
                    warnings.call_method1("warn", (warning.to_string(),))?;
                }
                res.ssl.resolve(Path::new(&home_dir))?;
                Ok(PyConnectionState {
                    inner: ConnectionState::new(
                        Credentials {
                            username,
                            password: res.password.password().unwrap_or_default().to_string(),
                            database: res.database.clone(),
                        },
                        ConnectionSslRequirement::Optional,
                    ),
                    parsed_dsn: res,
                    update: PyConnectionStateUpdate {
                        py_update: PyNone::get_bound(py).to_object(py),
                    },
                    message_buffer: Default::default(),
                })
            }
            Err(err) => Err(PyException::new_err(err.to_string())),
        }
    }

    #[setter]
    fn update(&mut self, py: Python, update: &Bound<PyAny>) {
        self.update.py_update = update.to_object(py);
    }

    fn is_ready(&self) -> bool {
        self.inner.is_ready()
    }

    fn read_ssl_response(&self) -> bool {
        self.inner.read_ssl_response()
    }

    fn drive_initial(&mut self) -> PyResult<()> {
        self.inner
            .drive(ConnectionDrive::Initial, &mut self.update)?;
        Ok(())
    }

    fn drive_message(&mut self, py: Python, data: &Bound<PyMemoryView>) -> PyResult<()> {
        let buffer = PyBuffer::<u8>::get_bound(data)?;
        if self.inner.read_ssl_response() {
            // SSL responses are always one character
            let response = [buffer.as_slice(py).unwrap().get(0).unwrap().get()];
            let response = SSLResponse::new(&response);
            self.inner
                .drive(ConnectionDrive::SslResponse(response), &mut self.update)?;
        } else {
            with_python_buffer(py, buffer, |buf| {
                self.message_buffer.push_fallible(buf, |message| {
                    self.inner
                        .drive(ConnectionDrive::Message(message), &mut self.update)
                })
            })?;
        }
        Ok(())
    }

    fn drive_ssl_ready(&mut self) -> PyResult<()> {
        self.inner
            .drive(ConnectionDrive::SslReady, &mut self.update)?;
        Ok(())
    }

    #[getter]
    fn host_candidates(&self) -> Vec<(String, String, u16)> {
        self.parsed_dsn
            .hosts
            .iter()
            .map(|host| match &host.0 {
                HostType::Hostname(name) => ("tcp".to_string(), name.clone(), host.1),
                HostType::IP(ip, _) => ("tcp".to_string(), ip.to_string(), host.1),
                HostType::Path(path) => ("unix".to_string(), path.clone(), host.1),
                HostType::Abstract(path) => ("unix".to_string(), path.clone(), host.1),
            })
            .collect()
    }

    #[getter]
    fn ssl_config(&self, py: Python) -> PyResult<Py<PyAny>> {
        let pickle = py.import_bound("pickle")?;
        let loads = pickle.getattr("loads")?;
        let Ssl::Enable(mode, ssl) = &self.parsed_dsn.ssl else {
            return Ok(PyNone::get_bound(py).to_object(py));
        };
        let vec = serde_pickle::to_vec(&(mode, ssl), SerOptions::new()).unwrap();
        Ok(loads
            .call1((PyByteArray::new_bound(py, &vec),))?
            .to_object(py))
    }
}

/// Attempt to stack-copy the data from a `PyBuffer`.
#[inline(always)]
fn with_python_buffer<T>(py: Python, data: PyBuffer<u8>, mut f: impl FnMut(&[u8]) -> T) -> T {
    let len = data.item_count();
    if len <= 128 {
        let mut slice = [0; 128];
        data.copy_to_slice(py, &mut slice).unwrap();
        f(&slice[..len])
    } else if len <= 1024 {
        let mut slice = [0; 1024];
        data.copy_to_slice(py, &mut slice).unwrap();
        f(&slice[..len])
    } else {
        f(&data.to_vec(py).unwrap())
    }
}

struct PyConnectionStateUpdate {
    py_update: Py<PyAny>,
}

impl ConnectionStateSend for PyConnectionStateUpdate {
    fn send_initial(
        &mut self,
        message: crate::protocol::definition::InitialBuilder,
    ) -> Result<(), std::io::Error> {
        Python::with_gil(|py| {
            let bytes = PyByteArray::new_bound(py, &message.to_vec());
            if let Err(e) = self.py_update.call_method1(py, "send", (bytes,)) {
                eprintln!("Error in send_initial: {:?}", e);
                e.print(py);
            }
        });
        Ok(())
    }

    fn send(
        &mut self,
        message: crate::protocol::definition::FrontendBuilder,
    ) -> Result<(), std::io::Error> {
        Python::with_gil(|py| {
            let bytes = PyBytes::new_bound(py, &message.to_vec());
            if let Err(e) = self.py_update.call_method1(py, "send", (bytes,)) {
                eprintln!("Error in send: {:?}", e);
                e.print(py);
            }
        });
        Ok(())
    }

    fn upgrade(&mut self) -> Result<(), std::io::Error> {
        Python::with_gil(|py| {
            if let Err(e) = self.py_update.call_method0(py, "upgrade") {
                eprintln!("Error in upgrade: {:?}", e);
                e.print(py);
            }
        });
        Ok(())
    }
}

impl ConnectionStateUpdate for PyConnectionStateUpdate {
    fn parameter(&mut self, name: &str, value: &str) {
        Python::with_gil(|py| {
            if let Err(e) = self.py_update.call_method1(py, "parameter", (name, value)) {
                eprintln!("Error in parameter: {:?}", e);
                e.print(py);
            }
        });
    }

    fn cancellation_key(&mut self, pid: i32, key: i32) {
        Python::with_gil(|py| {
            if let Err(e) = self
                .py_update
                .call_method1(py, "cancellation_key", (pid, key))
            {
                eprintln!("Error in cancellation_key: {:?}", e);
                e.print(py);
            }
        });
    }

    fn state_changed(&mut self, state: ConnectionStateType) {
        Python::with_gil(|py| {
            if let Err(e) = self
                .py_update
                .call_method1(py, "state_changed", (state as u8,))
            {
                eprintln!("Error in state_changed: {:?}", e);
                e.print(py);
            }
        });
    }

    fn auth(&mut self, auth: crate::connection::Authentication) {
        Python::with_gil(|py| {
            if let Err(e) = self.py_update.call_method1(py, "auth", (auth as u8,)) {
                eprintln!("Error in auth: {:?}", e);
                e.print(py);
            }
        });
    }
}
