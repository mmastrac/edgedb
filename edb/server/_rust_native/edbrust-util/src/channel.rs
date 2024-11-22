use nix::fcntl::{fcntl, FcntlArg, OFlag};
use nix::unistd::write;
use nix::{libc::EWOULDBLOCK, unistd::pipe};
use pyo3::{
    pyclass, pymethods,
    types::{PyAnyMethods, PyCFunction, PyDict, PyDictMethods, PyFunction, PyTuple},
    Bound, IntoPy, Py, PyResult, Python,
};
use pyo3::{FromPyObject, PyAny};
use std::pin::Pin;
use std::{
    cell::RefCell,
    ffi::c_void,
    future::poll_fn,
    marker::PhantomData,
    os::fd::{AsRawFd, IntoRawFd, OwnedFd},
    rc::Rc,
    sync::{Arc, Mutex},
};
use thiserror::Error;
use tokio::io::AsyncWrite;

/// A type alias for a callable that can be invoked with a Python interpreter.
type PythonCallable = Box<dyn FnOnce(Python) + Send + Sync + 'static>;

/// A Python script that performs a matching number of read operations for each
/// byte that is received by a given pipe.
const BOOT: &str = r#"""
import asyncio
import os
fd = os.fdopen(notify_fd, 'rb')

async def boot(fd, rx):
    loop = asyncio.get_running_loop()
    reader = asyncio.StreamReader(loop=loop)
    reader_protocol = asyncio.StreamReaderProtocol(reader)
    transport, _ = await loop.connect_read_pipe(lambda: reader_protocol, fd)
    try:
        while True:
            r = len(await reader.read(1024))
            if r == 0:
                break
            rx.recv(r)
    except asyncio.CancelledError as e:
        task.uncancel()
    finally:
        transport.close()

task = asyncio.create_task(boot(fd, rx))
"""#;

#[pyclass]
struct PythonReceiver {
    rx: std::sync::mpsc::Receiver<PythonCallable>,
}

#[pymethods]
impl PythonReceiver {
    pub fn recv(&self, py: Python, count: u16) {
        for _ in 0..count {
            if let Ok(f) = self.rx.recv() {
                f(py)
            }
        }
    }
}

#[pyclass]
/// A channel that multiplexes messages to multiple receivers.
pub struct ToPythonChannel {
    tx: std::sync::mpsc::Sender<PythonCallable>,
    tx_notify: Arc<OwnedFd>,
    /// Keep the task around so we don't cause errors
    #[allow(unused)]
    task: Py<PyAny>,
}

impl ToPythonChannel {
    pub fn new(py: Python) -> PyResult<Self> {
        let (tx, rx) = std::sync::mpsc::channel();
        let rx = PythonReceiver { rx };
        let (rx_notify, tx_notify) = pipe().unwrap();
        fcntl(rx_notify.as_raw_fd(), FcntlArg::F_SETFL(OFlag::O_NONBLOCK)).unwrap();
        fcntl(tx_notify.as_raw_fd(), FcntlArg::F_SETFL(OFlag::O_NONBLOCK)).unwrap();
        // Python will own the FD
        let notify_fd = rx_notify.into_raw_fd() as i64;

        let locals = PyDict::new_bound(py);
        locals.set_item("notify_fd", notify_fd)?;
        locals.set_item("rx", rx.into_py(py))?;
        py.run_bound(BOOT.trim(), None, Some(&locals))?;
        let task = locals.get_item("task")?.unwrap().unbind();

        Ok(Self {
            tx,
            tx_notify: tx_notify.into(),
            task,
        })
    }

    /// Registers a one-way call from Rust to Python, where the return value of the Python function is ignored.
    pub fn register<T>(&self, receiver: Bound<PyFunction>) -> ToPythonSender<T>
    where
        T: Send + Sync + IntoPy<Py<PyTuple>> + 'static,
    {
        let sender = ToPythonSender {
            notify: self.tx_notify.clone(),
            tx: self.tx.clone(),
            receiver: Arc::new(receiver.unbind()),
            _phantom: PhantomData,
        };
        sender
    }
}

pub struct ToPythonSender<T>
where
    T: Send + Sync + IntoPy<Py<PyTuple>> + 'static,
{
    receiver: Arc<Py<PyFunction>>,
    tx: std::sync::mpsc::Sender<PythonCallable>,
    notify: Arc<OwnedFd>,
    _phantom: PhantomData<T>,
}

impl<T> ToPythonSender<T>
where
    T: Send + Sync + IntoPy<Py<PyTuple>> + 'static,
{
    /// Send a message to the Python side. Not cancellation safe.
    pub async fn write(&self, args: T) -> Result<(), ChannelError> {
        let receiver = self.receiver.clone();
        self.tx
            .send(Box::new(move |py| {
                if let Err(err) = receiver.clone_ref(py).into_py(py).call1(py, args) {
                    // TODO?
                }
            }))
            .map_err(|_| ChannelError::Shutdown)?;
        // If we're shutting down, this may fail (but that's OK)
        loop {
            match write(&self.notify, &[0]) {
                Ok(_) => break,
                Err(nix::errno::Errno::EAGAIN) => {
                    // Spin
                    tokio::task::yield_now().await;
                    continue;
                }
                Err(e) => return Err(ChannelError::Io(e.into())),
            }
        }
        Ok(())
    }
}

#[derive(Error, Debug)]
pub enum ChannelError {
    #[error("Channel shutdown")]
    Shutdown,
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
}
