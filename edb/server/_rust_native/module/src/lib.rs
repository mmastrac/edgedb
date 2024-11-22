use edbrust_util::channel::ToPythonChannel;
use pyo3::{
    pyfunction, pymodule,
    types::{PyAnyMethods, PyModule, PyModuleMethods},
    wrap_pyfunction, Bound, IntoPy, Py, PyAny, PyResult, Python,
};

#[pyfunction]
fn create_to_python_channel(py: Python) -> PyResult<Py<PyAny>> {
    Ok(ToPythonChannel::new(py)?.into_py(py))
}

#[pymodule(name = "module")]
fn _rust_native(py: Python, m: &Bound<PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(create_to_python_channel, m)?)?;

    let child_module = PyModule::new_bound(py, "edb.server._rust_native.module._conn_pool")?;
    conn_pool::python::_conn_pool(py, &child_module)?;
    m.add("_conn_pool", &child_module)?;
    py.import_bound("sys")?
        .getattr("modules")?
        .set_item("edb.server._rust_native.module._conn_pool", child_module)?;

    let child_module = PyModule::new_bound(py, "edb.server._rust_native.module._pg_rust")?;
    pgrust::python::_pg_rust(py, &child_module)?;
    m.add("_pg_rust", &child_module)?;
    py.import_bound("sys")?
        .getattr("modules")?
        .set_item("edb.server._rust_native.module._pg_rust", child_module)?;

    Ok(())
}
