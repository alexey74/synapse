/*
 * This file is licensed under the Affero General Public License (AGPL) version 3.
 *
 * Copyright (C) 2024 New Vector, Ltd
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 *
 * See the GNU Affero General Public License for more details:
 * <https://www.gnu.org/licenses/agpl-3.0.html>.
 *
 * Originally licensed under the Apache License, Version 2.0:
 * <http://www.apache.org/licenses/LICENSE-2.0>.
 *
 * [This file includes modifications made by New Vector Limited]
 *
 */

//! Classes for representing Events.

use std::{collections::HashMap, sync::Arc};

use pyo3::{
    exceptions::PyKeyError,
    pyclass, pymethods,
    types::{PyAnyMethods, PyModule, PyModuleMethods},
    wrap_pyfunction, Bound, IntoPyObject, PyAny, PyResult, Python,
};
use pythonize::{depythonize, pythonize};

pub mod filter;
mod internal_metadata;

/// Called when registering modules with python.
pub fn register_module(py: Python<'_>, m: &Bound<'_, PyModule>) -> PyResult<()> {
    let child_module = PyModule::new(py, "events")?;
    child_module.add_class::<internal_metadata::EventInternalMetadata>()?;
    child_module.add_class::<JsonObject>()?;
    child_module.add_function(wrap_pyfunction!(filter::event_visible_to_server_py, m)?)?;

    m.add_submodule(&child_module)?;

    // We need to manually add the module to sys.modules to make `from
    // synapse.synapse_rust import events` work.
    py.import("sys")?
        .getattr("modules")?
        .set_item("synapse.synapse_rust.events", child_module)?;

    Ok(())
}

struct Hashes {
    sha256: Option<[u8; 32]>,
    others: std::collections::HashMap<Box<str>, Box<str>>,
}

#[pyclass]
struct EventInner {
    #[pyo3(get)]
    content: JsonObject,
    depth: i64,
    hashes: Hashes,
    origin_server_ts: i64,
    sender: Box<str>,
    state_key: Option<Box<str>>,
    type_: Box<str>,

    unsigned: JsonObject,
    signatures: HashMap<Box<str>, HashMap<Box<str>, Box<str>>>,
}

#[pyclass(mapping)]
#[derive(Clone)]
struct JsonObject {
    object: Arc<HashMap<Box<str>, serde_json::Value>>,
}

#[pymethods]
impl JsonObject {
    #[new]
    fn new<'a, 'py>(object: &'a Bound<'py, PyAny>) -> PyResult<Self> {
        Ok(Self {
            object: Arc::new(depythonize(&object)?),
        })
    }

    fn __len__(&self) -> usize {
        self.object.len()
    }

    fn __contains__(&self, key: &str) -> bool {
        self.object.contains_key(key)
    }

    fn __getitem__<'py>(&self, py: Python<'py>, key: &str) -> PyResult<Option<Bound<'py, PyAny>>> {
        let Some(value) = self.object.get(key) else {
            return Err(PyKeyError::new_err(key.to_string()));
        };
        Ok(Some(pythonize(py, value)?))
    }
}
