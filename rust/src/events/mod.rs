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
use serde::{Deserialize, Serialize};

pub mod filter;
mod internal_metadata;

/// Called when registering modules with python.
pub fn register_module(py: Python<'_>, m: &Bound<'_, PyModule>) -> PyResult<()> {
    let child_module = PyModule::new(py, "events")?;
    child_module.add_class::<internal_metadata::EventInternalMetadata>()?;
    child_module.add_class::<JsonObject>()?;
    child_module.add_class::<Event>()?;
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

#[derive(Serialize, Deserialize)]
#[pyclass(mapping)]
#[derive(Clone)]
#[serde(transparent)]
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

#[derive(Serialize, Deserialize)]
#[pyclass]
struct EventCommonFields {
    #[pyo3(get)]
    content: JsonObject,
    #[pyo3(get)]
    depth: i64,
    hashes: HashMap<String, String>,
    #[pyo3(get)]
    origin_server_ts: i64,
    #[pyo3(get)]
    sender: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[pyo3(get)]
    state_key: Option<String>,
    #[serde(rename = "type")]
    #[pyo3(get, name = "type")]
    type_: String,

    unsigned: JsonObject,
    signatures: HashMap<Box<str>, HashMap<Box<str>, Box<str>>>,

    #[serde(flatten)]
    other_fields: HashMap<String, serde_json::Value>,
}

#[pyclass]
struct Event {
    inner: EventFormatEnum,
}

#[pymethods]
impl Event {
    #[new]
    fn new<'a, 'py>(format: u8, event_dict: &'a Bound<'py, PyAny>) -> PyResult<Self> {
        if format != 3 {
            return Err(PyKeyError::new_err(format!(
                "Unsupported event format version: {}",
                format
            )));
        }

        let event_format_v3: EventFormatV3Container = depythonize(event_dict)?;
        Ok(Self {
            inner: EventFormatEnum::V3(event_format_v3),
        })
    }

    #[getter]
    fn room_id(&self) -> Option<&str> {
        match &self.inner {
            EventFormatEnum::V3(format) => format.specific_fields.room_id.as_deref(),
            // ...
        }
    }

    fn get_pdu_json<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        match &self.inner {
            EventFormatEnum::V3(format) => Ok(pythonize(py, format)?),
            // ...
        }
    }
}

enum EventFormatEnum {
    V3(EventFormatV3Container),
    // ...
}

#[derive(Serialize, Deserialize)]
struct EventFormatV3 {
    auth_events: Vec<String>,
    prev_events: Vec<String>,
    room_id: Option<String>,
}

#[derive(Serialize, Deserialize)]
struct EventFormatV3Container {
    #[serde(flatten)]
    specific_fields: EventFormatV3,
    #[serde(flatten)]
    common_fields: EventCommonFields,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_basic_v3_roundtrip() {
        let json = r#"{"auth_events":[],"prev_events":[],"type":"m.room.create","sender":"@anon-20260225_142731-20:localhost:8800","content":{"room_version":"10","creator":"@anon-20260225_142731-20:localhost:8800"},"depth":1,"room_id":"!qVoJSympOqdUQRUfiC:localhost:8800","state_key":"","origin_server_ts":1772029657149,"hashes":{"sha256":"RIDkn4CrExGMOfRZlHl//1weAro5QC/q2D76YcyAUqk"},"signatures":{"localhost:8800":{"ed25519:a_GMSl":"GU7WmvI2Kd5kLrXKrWpRbUfEiVKGgH0sxQNEpBMMvgF3QhHN25AubVMmIClht5r/c+Iihb1xsq1j5Sw+RGfiDg"}},"unsigned":{"age_ts":1772029657149}}"#;
        let event_value: serde_json::Value = serde_json::from_str(json).unwrap();

        let event: EventFormatV3Container = serde_json::from_str(json).unwrap();
        let parsed_value = serde_json::to_value(&event).unwrap();

        assert_eq!(event.common_fields.type_, "m.room.create".to_string());

        assert_eq!(
            event.specific_fields.room_id,
            Some("!qVoJSympOqdUQRUfiC:localhost:8800".to_string())
        );

        assert_eq!(
            event.common_fields.other_fields.get("auth_events").unwrap(),
            &serde_json::Value::Array(vec![])
        );

        assert_eq!(event_value, parsed_value);
    }
}
