// use std::future::Future;
// use pyo3::{types::{PyCFunction, PyFunction}, FromPyObject, PyResult, ToPyObject};

// ///! Bi-directional RPC between Rust and Python.
// ///
// /// This module provides a simple RPC framework for communication between Rust and Python.

// /// Creates a Python RPC function that will call the given Rust function. The returned future must be used in
// /// another thread with a Tokio runtime.
// pub fn create_python_rpc_client<T, R>(f: impl Fn(T) -> R) -> PyResult<PyCFunction, impl Future>
//     where T: Send + FromPyObject + 'static,
//     R: Send + ToPyObject + 'static
// {

// }
