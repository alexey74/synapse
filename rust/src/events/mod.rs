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

use std::{
    collections::HashMap,
    sync::{Arc, RwLock},
};

use pyo3::{
    exceptions::PyKeyError,
    pyclass, pymethods,
    types::{PyAnyMethods, PyIterator, PyMapping, PyMappingMethods, PyModule, PyModuleMethods},
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
    child_module.add_class::<Signatures>()?;
    child_module.add_class::<DomainSignatures>()?;
    child_module.add_function(wrap_pyfunction!(filter::event_visible_to_server_py, m)?)?;

    m.add_submodule(&child_module)?;

    // We need to manually add the module to sys.modules to make `from
    // synapse.synapse_rust import events` work.
    py.import("sys")?
        .getattr("modules")?
        .set_item("synapse.synapse_rust.events", child_module)?;

    Ok(())
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
            object: Arc::new(depythonize(object)?),
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

    fn __iter__<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyIterator>> {
        PyIterator::from_object(
            &self
                .object
                .keys()
                .map(|k| &**k)
                .collect::<Vec<_>>()
                .into_pyobject(py)?,
        )
    }
}

#[derive(Serialize, Deserialize, Clone)]
#[pyclass(mapping)]
#[serde(transparent)]
struct Signatures {
    signatures: Arc<RwLock<HashMap<Box<str>, DomainSignatures>>>,
}

#[pymethods]
impl Signatures {
    fn __getitem__(&self, key: &str) -> PyResult<Option<DomainSignatures>> {
        let signatures = self.signatures.read().unwrap();
        let Some(value) = signatures.get(key) else {
            return Err(PyKeyError::new_err(key.to_string()));
        };
        Ok(Some(value.clone()))
    }

    fn __len__(&self) -> usize {
        let signatures = self.signatures.read().unwrap();
        signatures.len()
    }

    fn __iter__<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyIterator>> {
        let signatures = self.signatures.read().unwrap();
        PyIterator::from_object(
            &signatures
                .keys()
                .map(|k| &**k)
                .collect::<Vec<_>>()
                .into_pyobject(py)?,
        )
    }

    fn __contains__(&self, key: &str) -> bool {
        let signatures = self.signatures.read().unwrap();
        signatures.contains_key(key)
    }

    fn __setitem__(&mut self, key: String, value: DomainSignatures) -> PyResult<()> {
        let mut signatures = self.signatures.write().unwrap();
        signatures.insert(key.into_boxed_str(), value);
        Ok(())
    }

    fn __delitem__(&mut self, key: &str) -> PyResult<()> {
        let mut signatures = self.signatures.write().unwrap();
        if signatures.remove(key).is_none() {
            return Err(PyKeyError::new_err(key.to_string()));
        }
        Ok(())
    }

    fn clear(&mut self) -> PyResult<()> {
        let mut signatures = self.signatures.write().unwrap();
        signatures.clear();
        Ok(())
    }

    fn pop<'py>(
        &mut self,
        py: Python<'py>,
        key: &str,
        default: Option<Bound<'py, PyAny>>,
    ) -> PyResult<Bound<'py, PyAny>> {
        let mut signatures = self.signatures.write().unwrap();
        match signatures.remove(key) {
            Some(value) => Ok(Some(value).into_pyobject(py)?),
            None => Ok(default.unwrap_or_else(|| py.None().into_bound(py))),
        }
    }

    fn keys<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        let signatures = self.signatures.read().unwrap();
        signatures
            .keys()
            .map(|k| &**k)
            .collect::<Vec<_>>()
            .into_pyobject(py)
    }

    fn values<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        let signatures = self.signatures.read().unwrap();
        signatures
            .values()
            .cloned()
            .collect::<Vec<_>>()
            .into_pyobject(py)
    }

    fn items<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        let signatures = self.signatures.read().unwrap();
        let items: Vec<_> = signatures.iter().map(|(k, v)| (&**k, v.clone())).collect();
        items.into_pyobject(py)
    }

    #[pyo3(signature = (key, default=None))]
    fn get<'py>(
        &self,
        py: Python<'py>,
        key: &str,
        default: Option<Bound<'py, PyAny>>,
    ) -> PyResult<Bound<'py, PyAny>> {
        let signatures = self.signatures.read().unwrap();
        match signatures.get(key) {
            Some(value) => Ok(Some(value.clone()).into_pyobject(py)?),
            None => Ok(default.unwrap_or_else(|| py.None().into_bound(py))),
        }
    }

    fn update(&mut self, other: &Bound<'_, PyMapping>) -> PyResult<()> {
        let mut signatures = self.signatures.write().unwrap();
        for key in other.keys()? {
            let key_str = key.extract::<String>()?;
            let value: HashMap<String, String> = other.get_item(&key)?.extract()?;
            let value = DomainSignatures {
                signatures: Arc::new(RwLock::new(
                    value
                        .into_iter()
                        .map(|(k, v)| (k.into_boxed_str(), v.into_boxed_str()))
                        .collect(),
                )),
            };
            signatures.insert(key_str.into_boxed_str(), value);
        }
        Ok(())
    }
}

#[derive(Serialize, Deserialize, Clone)]
#[pyclass(mapping)]
#[serde(transparent)]
struct DomainSignatures {
    signatures: Arc<RwLock<HashMap<Box<str>, Box<str>>>>,
}

#[pymethods]
impl DomainSignatures {
    fn __getitem__<'py>(&self, py: Python<'py>, key: &str) -> PyResult<Bound<'py, PyAny>> {
        let signatures = self.signatures.read().unwrap();
        let Some(value) = signatures.get(key) else {
            return Err(PyKeyError::new_err(key.to_string()));
        };
        Ok(Some(&**value).into_pyobject(py)?)
    }

    fn __len__(&self) -> usize {
        let signatures = self.signatures.read().unwrap();
        signatures.len()
    }

    fn __iter__<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        // This is a bit inefficient, but it avoids having to implement a custom
        // iterator type.
        let signatures = self.signatures.read().unwrap();

        signatures
            .keys()
            .map(|k| &**k)
            .collect::<Vec<_>>()
            .into_pyobject(py)
    }

    fn __contains__(&self, key: &str) -> bool {
        let signatures = self.signatures.read().unwrap();
        signatures.contains_key(key)
    }

    fn __setitem__(&mut self, key: &str, value: &str) {
        let mut signatures = self.signatures.write().unwrap();
        signatures.insert(Box::from(key), Box::from(value));
    }

    fn __delitem__(&mut self, key: &str) -> PyResult<()> {
        let mut signatures = self.signatures.write().unwrap();
        if signatures.remove(key).is_none() {
            return Err(PyKeyError::new_err(key.to_string()));
        }
        Ok(())
    }

    fn keys<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        let signatures = self.signatures.read().unwrap();
        signatures
            .keys()
            .map(|k| &**k)
            .collect::<Vec<_>>()
            .into_pyobject(py)
    }

    fn values<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        let signatures = self.signatures.read().unwrap();
        signatures
            .values()
            .map(|v| &**v)
            .collect::<Vec<_>>()
            .into_pyobject(py)
    }

    fn items<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        let signatures = self.signatures.read().unwrap();
        let items: Vec<_> = signatures.iter().map(|(k, v)| (&**k, &**v)).collect();
        items.into_pyobject(py)
    }

    #[pyo3(signature = (key, default=None))]
    fn get<'py>(
        &self,
        py: Python<'py>,
        key: &str,
        default: Option<Bound<'py, PyAny>>,
    ) -> PyResult<Bound<'py, PyAny>> {
        let signatures = self.signatures.read().unwrap();
        match signatures.get(key) {
            Some(value) => Ok(Some(&**value).into_pyobject(py)?),
            None => Ok(default.unwrap_or_else(|| py.None().into_bound(py))),
        }
    }

    fn clear(&mut self) -> PyResult<()> {
        let mut signatures = self.signatures.write().unwrap();
        signatures.clear();
        Ok(())
    }

    fn pop<'py>(
        &mut self,
        py: Python<'py>,
        key: &str,
        default: Option<Bound<'py, PyAny>>,
    ) -> PyResult<Bound<'py, PyAny>> {
        let mut signatures = self.signatures.write().unwrap();
        match signatures.remove(key) {
            Some(value) => Ok(Some(&*value).into_pyobject(py)?),
            None => Ok(default.unwrap_or_else(|| py.None().into_bound(py))),
        }
    }

    fn update(&mut self, other: &Bound<'_, PyMapping>) -> PyResult<()> {
        let mut signatures: std::sync::RwLockWriteGuard<'_, HashMap<Box<str>, Box<str>>> =
            self.signatures.write().unwrap();
        for key in other.keys()? {
            let key_str = key.extract::<String>()?;
            let value: String = other.get_item(&key)?.extract()?;
            signatures.insert(key_str.into_boxed_str(), value.into_boxed_str());
        }
        Ok(())
    }
}

#[derive(Serialize, Deserialize)]
struct EventCommonFields {
    content: JsonObject,
    hashes: HashMap<String, String>,
    origin_server_ts: i64,
    sender: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    state_key: Option<String>,
    #[serde(rename = "type")]
    type_: String,

    room_id: Option<String>,

    unsigned: JsonObject,
    signatures: Signatures,

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
            EventFormatEnum::V3(format) => format.common_fields.room_id.as_deref(),
            // ...
        }
    }

    #[getter]
    fn signatures(&self) -> PyResult<Signatures> {
        match &self.inner {
            EventFormatEnum::V3(format) => Ok(format.common_fields.signatures.clone()),
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
            event.common_fields.room_id,
            Some("!qVoJSympOqdUQRUfiC:localhost:8800".to_string())
        );

        assert_eq!(event_value, parsed_value);
    }

    #[test]
    fn test_signatures_serde() {
        let json = r#"{"localhost:8800":{"ed25519:a_GMSl":"GU7WmvI2Kd5kLrXKrWpRbUfEiVKGgH0sxQNEpBMMvgF3QhHN25AubVMmIClht5r/c+Iihb1xsq1j5Sw+RGfiDg"}}"#;
        let signatures: Signatures = serde_json::from_str(json).unwrap();

        let signatures_inner = signatures.signatures.read().unwrap();
        assert!(signatures_inner.contains_key("localhost:8800"));
        let domain_signatures = signatures_inner.get("localhost:8800").unwrap();
        let signatures_map = domain_signatures.signatures.read().unwrap();
        assert!(signatures_map.contains_key("ed25519:a_GMSl"));
        assert_eq!(
            signatures_map.get("ed25519:a_GMSl").unwrap().as_ref(),
            "GU7WmvI2Kd5kLrXKrWpRbUfEiVKGgH0sxQNEpBMMvgF3QhHN25AubVMmIClht5r/c+Iihb1xsq1j5Sw+RGfiDg"
        );

        // Now test serialization
        let serialized_json = serde_json::to_string(&signatures).unwrap();

        assert_eq!(
            serde_json::from_str::<serde_json::Value>(&serialized_json).unwrap(),
            serde_json::from_str::<serde_json::Value>(json).unwrap()
        );
    }
}
