use pyo3::{types::PyFunction, Bound, PyResult, Python};

fn create_stream<S>(stream: S) -> PythonStream {
    PythonStream {}
}

struct PythonStream {}

impl PythonStream {
    /// Drive a Python receiver and provide a writer function.
    pub fn run(py: Python, receiver: Bound<PyFunction>) -> PyResult<PyFunction> {
        unimplemented!()
    }
}
