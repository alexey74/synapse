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
    str::FromStr,
    sync::{Arc, RwLock},
};

use pyo3::{
    exceptions::{PyAttributeError, PyException, PyKeyError, PyValueError},
    pyclass, pymethods,
    types::{
        PyAnyMethods, PyDict, PyDictMethods, PyIterator, PyList, PyMapping, PyMappingMethods,
        PyModule, PyModuleMethods,
    },
    wrap_pyfunction, Bound, IntoPyObject, Py, PyAny, PyResult, Python,
};
use pythonize::{depythonize, pythonize};
use serde::{Deserialize, Serialize};

use crate::{
    events::{
        constants::{get_room_version_py, RoomVersion},
        internal_metadata::EventInternalMetadata,
        utils::calculate_event_id,
    },
    identifier::EventID,
};

mod constants;
pub mod filter;
mod internal_metadata;
mod utils;

/// Called when registering modules with python.
pub fn register_module(py: Python<'_>, m: &Bound<'_, PyModule>) -> PyResult<()> {
    let child_module = PyModule::new(py, "events")?;
    child_module.add_class::<EventInternalMetadata>()?;
    child_module.add_class::<JsonObject>()?;
    child_module.add_class::<JsonObjectMutable>()?;
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
#[pyclass(mapping, frozen)]
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

    fn __getitem__<'py>(&self, py: Python<'py>, key: &str) -> PyResult<Bound<'py, PyAny>> {
        let Some(value) = self.object.get(key) else {
            return Err(PyKeyError::new_err(key.to_string()));
        };
        Ok(pythonize(py, value)?)
    }

    fn __iter__<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyIterator>> {
        Ok(PyIterator::from_object(
            &self
                .object
                .keys()
                .map(|k| &**k)
                .collect::<Vec<_>>()
                .into_pyobject(py)?,
        )?)
    }

    fn keys<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        Ok(self
            .object
            .keys()
            .map(|k| &**k)
            .collect::<Vec<_>>()
            .into_pyobject(py)?)
    }

    fn values<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        let values: Vec<_> = self
            .object
            .values()
            .map(|v| pythonize(py, v))
            .collect::<Result<Vec<_>, _>>()?;
        Ok(values.into_pyobject(py)?)
    }

    fn items<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        let items: Vec<_> = self
            .object
            .iter()
            .map(|(k, v)| PyResult::Ok((k.as_ref(), pythonize(py, v)?)))
            .collect::<PyResult<Vec<_>>>()?;
        Ok(items.into_pyobject(py)?)
    }

    #[pyo3(signature = (key, default=None))]
    fn get<'py>(
        &self,
        py: Python<'py>,
        key: &str,
        default: Option<Bound<'py, PyAny>>,
    ) -> PyResult<Bound<'py, PyAny>> {
        match self.object.get(key) {
            Some(value) => Ok(pythonize(py, value)?),
            None => Ok(default.into_pyobject(py)?),
        }
    }

    fn as_dict<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        Ok(pythonize(py, &self)?)
    }

    fn __eq__(&self, other: Bound<'_, PyMapping>) -> bool {
        let Ok(other_dict) = depythonize(&other) else {
            return false;
        };

        *self.object == other_dict
    }
}

#[derive(Serialize, Deserialize, Clone)]
#[pyclass(mapping, frozen)]
#[serde(transparent)]
struct JsonObjectMutable {
    object: Arc<RwLock<HashMap<Box<str>, serde_json::Value>>>,
}

#[pymethods]
impl JsonObjectMutable {
    #[new]
    fn new<'a, 'py>(object: &'a Bound<'py, PyAny>) -> PyResult<Self> {
        Ok(Self {
            object: Arc::new(RwLock::new(depythonize(object)?)),
        })
    }

    fn __len__(&self) -> usize {
        let obj = self.object.read().unwrap();
        obj.len()
    }

    fn __contains__(&self, key: &str) -> bool {
        let obj = self.object.read().unwrap();
        obj.contains_key(key)
    }

    fn __getitem__<'py>(&self, py: Python<'py>, key: &str) -> PyResult<Bound<'py, PyAny>> {
        let obj = self.object.read().unwrap();
        let Some(value) = obj.get(key) else {
            return Err(PyKeyError::new_err(key.to_string()));
        };
        Ok(pythonize(py, value)?)
    }

    fn __setitem__(&self, key: String, value: &Bound<'_, PyAny>) -> PyResult<()> {
        let mut obj = self.object.write().unwrap();
        obj.insert(key.into_boxed_str(), depythonize(value)?);
        Ok(())
    }

    fn __delitem__(&self, key: &str) -> PyResult<()> {
        let mut obj = self.object.write().unwrap();
        if obj.remove(key).is_none() {
            return Err(PyKeyError::new_err(key.to_string()));
        }
        Ok(())
    }

    fn __iter__<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyIterator>> {
        let obj = self.object.read().unwrap();
        Ok(PyIterator::from_object(
            &obj.keys()
                .map(|k| &**k)
                .collect::<Vec<_>>()
                .into_pyobject(py)?,
        )?)
    }

    fn keys<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        let obj = self.object.read().unwrap();
        Ok(obj
            .keys()
            .map(|k| &**k)
            .collect::<Vec<_>>()
            .into_pyobject(py)?)
    }

    fn values<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        let obj = self.object.read().unwrap();
        let values: Vec<_> = obj
            .values()
            .map(|v| pythonize(py, v))
            .collect::<Result<Vec<_>, _>>()?;
        Ok(values.into_pyobject(py)?)
    }

    fn items<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        let obj = self.object.read().unwrap();
        let items: Vec<_> = obj
            .iter()
            .map(|(k, v)| PyResult::Ok((k.as_ref(), pythonize(py, v)?)))
            .collect::<PyResult<Vec<_>>>()?;
        Ok(items.into_pyobject(py)?)
    }

    #[pyo3(signature = (key, default=None))]
    fn get<'py>(
        &self,
        py: Python<'py>,
        key: &str,
        default: Option<Bound<'py, PyAny>>,
    ) -> PyResult<Bound<'py, PyAny>> {
        let obj = self.object.read().unwrap();
        match obj.get(key) {
            Some(value) => Ok(pythonize(py, value)?),
            None => Ok(default.into_pyobject(py)?),
        }
    }

    fn clear(&self) -> PyResult<()> {
        let mut obj = self.object.write().unwrap();
        obj.clear();
        Ok(())
    }

    fn update(&self, other: &Bound<'_, PyMapping>) -> PyResult<()> {
        let mut obj = self.object.write().unwrap();
        for key in other.keys()? {
            let key_str = key.extract::<String>()?;
            let value = depythonize(&other.get_item(&key)?)?;
            obj.insert(key_str.into_boxed_str(), value);
        }
        Ok(())
    }

    #[pyo3(signature = (key, default=None))]
    fn pop<'py>(
        &self,
        py: Python<'py>,
        key: &str,
        default: Option<Bound<'py, PyAny>>,
    ) -> PyResult<Bound<'py, PyAny>> {
        let mut obj = self.object.write().unwrap();
        match obj.remove(key) {
            Some(value) => Ok(pythonize(py, &value)?),
            None => Ok(default.into_pyobject(py)?),
        }
    }
}

#[derive(Serialize, Deserialize, Clone)]
#[pyclass(mapping, frozen)]
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

    fn __setitem__(&self, key: String, value: DomainSignatures) -> PyResult<()> {
        let mut signatures = self.signatures.write().unwrap();
        signatures.insert(key.into_boxed_str(), value);
        Ok(())
    }

    fn __delitem__(&self, key: &str) -> PyResult<()> {
        let mut signatures = self.signatures.write().unwrap();
        if signatures.remove(key).is_none() {
            return Err(PyKeyError::new_err(key.to_string()));
        }
        Ok(())
    }

    fn clear(&self) -> PyResult<()> {
        let mut signatures = self.signatures.write().unwrap();
        signatures.clear();
        Ok(())
    }

    #[pyo3(signature = (key, default=None))]
    fn pop<'py>(
        &self,
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

    fn update(&self, other: &Bound<'_, PyMapping>) -> PyResult<()> {
        // Check if we're pointing at the same object, if so do nothing.
        if let Ok(other_signatures) = other.cast::<Signatures>() {
            if Arc::ptr_eq(&self.signatures, &other_signatures.get().signatures) {
                return Ok(());
            }
        }

        let mut signatures = self.signatures.write().unwrap();
        for key in other.keys()? {
            let key_str = key.extract::<String>()?;
            let value = other.get_item(&key)?;
            if let Ok(domain_signatures) = value.cast::<DomainSignatures>() {
                signatures.insert(key_str.into_boxed_str(), domain_signatures.get().clone());
                continue;
            } else if let Ok(value_dict) = value.extract::<HashMap<String, String>>() {
                let domain_signatures = DomainSignatures {
                    signatures: Arc::new(RwLock::new(
                        value_dict
                            .into_iter()
                            .map(|(k, v)| (k.into_boxed_str(), v.into_boxed_str()))
                            .collect(),
                    )),
                };
                signatures.insert(key_str.into_boxed_str(), domain_signatures);
                continue;
            } else if let Ok(mapping) = value.cast::<PyMapping>() {
                let mut domain_signatures_map = HashMap::new();
                for sub_key in mapping.keys()? {
                    let sub_key_str = sub_key.extract::<String>()?;
                    let sub_value = mapping.get_item(&sub_key)?;
                    let sub_value_str = sub_value.extract::<String>()?;
                    domain_signatures_map
                        .insert(sub_key_str.into_boxed_str(), sub_value_str.into_boxed_str());
                }
                let domain_signatures = DomainSignatures {
                    signatures: Arc::new(RwLock::new(domain_signatures_map)),
                };
                signatures.insert(key_str.into_boxed_str(), domain_signatures);
                continue;
            } else {
                return Err(PyValueError::new_err(format!(
                    "Value for key '{}' must be a DomainSignatures or a mapping",
                    key_str
                )));
            }
        }
        Ok(())
    }
}

#[derive(Serialize, Deserialize, Clone)]
#[pyclass(mapping, frozen)]
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

    fn __iter__<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyIterator>> {
        // This is a bit inefficient, but it avoids having to implement a custom
        // iterator type.
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

    fn __setitem__(&self, key: &str, value: &str) {
        let mut signatures = self.signatures.write().unwrap();
        signatures.insert(Box::from(key), Box::from(value));
    }

    fn __delitem__(&self, key: &str) -> PyResult<()> {
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

    fn clear(&self) -> PyResult<()> {
        let mut signatures = self.signatures.write().unwrap();
        signatures.clear();
        Ok(())
    }

    fn pop<'py>(
        &self,
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

    fn update(&self, other: &Bound<'_, PyMapping>) -> PyResult<()> {
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
    depth: i64,
    hashes: HashMap<String, String>,
    origin_server_ts: i64,
    sender: Box<str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    state_key: Option<Box<str>>,
    #[serde(rename = "type")]
    type_: Box<str>,

    room_id: Option<Box<str>>,

    unsigned: JsonObjectMutable,
    signatures: Signatures,

    #[serde(flatten)]
    other_fields: HashMap<Box<str>, serde_json::Value>,
}

#[pyclass(frozen, weakref)]
struct Event {
    inner: EventFormatEnum,
    event_id: EventID,
    internal_metadata: Py<EventInternalMetadata>,
    room_version: RoomVersion,
    rejected_reason: Option<Box<str>>,
}

#[pymethods]
impl Event {
    #[new]
    fn new<'a, 'py>(
        py: Python<'py>,
        event_dict: &'a Bound<'py, PyAny>,
        room_version: &'a Bound<'py, PyAny>,
        internal_metadata_dict: &'a Bound<'py, PyDict>,
        rejected_reason: Option<String>,
    ) -> PyResult<Self> {
        let room_version = {
            let r = room_version.getattr("identifier")?;
            let room_version_str = r.extract::<&str>()?;
            RoomVersion::from_str(room_version_str)
                .map_err(|e| PyValueError::new_err(format!("Unsupported room version: {}", e)))?
        };

        let rejected_reason = rejected_reason.map(String::into_boxed_str);

        // Check we're the right room version
        match room_version {
            RoomVersion::V4
            | RoomVersion::V5
            | RoomVersion::V6
            | RoomVersion::V7
            | RoomVersion::V8
            | RoomVersion::V9
            | RoomVersion::V10
            | RoomVersion::V11
            | RoomVersion::OrgMatrixMsc1767_10
            | RoomVersion::OrgMatrixMsc3757_10
            | RoomVersion::OrgMatrixMsc3757_11 => {}
            _ => return Err(PyValueError::new_err("Unsupported room version")),
        }

        let event_format_v3: EventFormatV3Container = depythonize(event_dict)?;

        let internal_metadata = Py::new(py, EventInternalMetadata::new(internal_metadata_dict)?)?;

        let event_value = serde_json::to_value(&event_format_v3)
            .map_err(|err| PyException::new_err(format!("Failed to serialize event: {}", err)))?;
        let event_id = calculate_event_id(&event_value, &room_version).map_err(|err| {
            PyException::new_err(format!("Failed to calculate event_id: {}", err))
        })?;

        Ok(Self {
            inner: EventFormatEnum::V3(event_format_v3),
            event_id,
            room_version,
            rejected_reason,
            internal_metadata,
        })
    }

    fn get_dict<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        match &self.inner {
            EventFormatEnum::V3(format) => Ok(pythonize(py, format)?),
            // ...
        }
    }

    #[pyo3(signature = (time_now = None))]
    fn get_pdu_json<'py>(
        &self,
        py: Python<'py>,
        time_now: Option<i64>,
    ) -> PyResult<Bound<'py, PyAny>> {
        // TODO: We need to do a bunch of changes here.
        match &self.inner {
            EventFormatEnum::V3(format) => Ok(pythonize(py, format)?),
            // ...
        }
    }

    fn get_templated_pdu_json<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        let obj = self.get_dict(py)?;
        let dict = obj.cast::<PyDict>()?;
        dict.del_item("hashes").ok();

        Ok(obj)
    }

    #[getter]
    fn event_id(&self) -> &str {
        &self.event_id
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

    #[getter]
    fn content(&self) -> PyResult<JsonObject> {
        match &self.inner {
            EventFormatEnum::V3(format) => Ok(format.common_fields.content.clone()),
            // ...
        }
    }

    #[getter]
    fn depth(&self) -> PyResult<i64> {
        match &self.inner {
            EventFormatEnum::V3(format) => Ok(format.common_fields.depth),
            // ...
        }
    }

    #[getter]
    fn hashes(&self) -> PyResult<&HashMap<String, String>> {
        match &self.inner {
            EventFormatEnum::V3(format) => Ok(&format.common_fields.hashes),
            // ...
        }
    }

    #[getter]
    fn origin_server_ts(&self) -> PyResult<i64> {
        match &self.inner {
            EventFormatEnum::V3(format) => Ok(format.common_fields.origin_server_ts),
            // ...
        }
    }

    #[getter]
    fn sender(&self) -> PyResult<&str> {
        match &self.inner {
            EventFormatEnum::V3(format) => Ok(&format.common_fields.sender),
            // ...
        }
    }

    #[getter(state_key)]
    fn state_key_attr(&self) -> PyResult<&str> {
        let state_key = match &self.inner {
            EventFormatEnum::V3(format) => &format.common_fields.state_key,
            // ...
        };

        let Some(state_key) = state_key.as_deref() else {
            return Err(PyAttributeError::new_err("state_key"));
        };
        Ok(state_key)
    }

    #[getter]
    fn r#type(&self) -> PyResult<&str> {
        match &self.inner {
            EventFormatEnum::V3(format) => Ok(&format.common_fields.type_),
            // ...
        }
    }

    #[getter]
    fn unsigned(&self) -> PyResult<JsonObjectMutable> {
        match &self.inner {
            EventFormatEnum::V3(format) => Ok(format.common_fields.unsigned.clone()),
            // ...
        }
    }

    #[getter]
    fn internal_metadata(&self, py: Python<'_>) -> PyResult<Py<EventInternalMetadata>> {
        Ok(Py::clone_ref(&self.internal_metadata, py))
    }

    #[getter]
    fn rejected_reason(&self) -> Option<&str> {
        self.rejected_reason.as_deref()
    }

    #[getter]
    fn room_version<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        get_room_version_py(&self.room_version, py)
    }

    fn prev_event_ids(&self) -> PyResult<Vec<String>> {
        match &self.inner {
            EventFormatEnum::V3(format) => Ok(format
                .specific_fields
                .prev_events
                .iter()
                .map(|s| s.to_string())
                .collect()),
            // ...
        }
    }

    fn auth_event_ids(&self) -> PyResult<Vec<String>> {
        match &self.inner {
            EventFormatEnum::V3(format) => Ok(format
                .specific_fields
                .auth_events
                .iter()
                .map(|s| s.to_string())
                .collect()),
            // ...
        }
    }

    #[getter]
    fn membership<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        let content = self.content()?;
        content.__getitem__(py, "membership")
    }

    #[getter]
    fn redacts<'py>(&self, py: Python<'py>) -> PyResult<Option<Bound<'py, PyAny>>> {
        let value = match self.room_version {
            RoomVersion::V1
            | RoomVersion::V2
            | RoomVersion::V3
            | RoomVersion::V4
            | RoomVersion::V5
            | RoomVersion::V6
            | RoomVersion::V7
            | RoomVersion::V8
            | RoomVersion::V9
            | RoomVersion::V10 => {
                let other_fields = match &self.inner {
                    EventFormatEnum::V3(format) => &format.common_fields.other_fields,
                    // ...
                };

                let Some(value) = other_fields.get("redacts") else {
                    return Ok(None);
                };

                value
            }
            RoomVersion::V11
            | RoomVersion::V12
            | RoomVersion::OrgMatrixMsc1767_10
            | RoomVersion::OrgMatrixMsc3757_10
            | RoomVersion::OrgMatrixMsc3757_11
            | RoomVersion::OrgMatrixHydra11 => {
                let content = match &self.inner {
                    EventFormatEnum::V3(format) => &format.common_fields.content,
                    // ...
                };

                let Some(value) = content.object.get("redacts") else {
                    return Ok(None);
                };

                value
            }
            RoomVersion::Custom(_) => todo!(),
        };

        Ok(Some(pythonize(py, value)?))
    }

    fn is_state(&self) -> bool {
        match &self.inner {
            EventFormatEnum::V3(format) => format.common_fields.state_key.is_some(),
            // ...
        }
    }

    fn get_state_key(&self) -> Option<&str> {
        match &self.inner {
            EventFormatEnum::V3(format) => format.common_fields.state_key.as_deref(),
            // ...
        }
    }

    fn __contains__<'py>(&self, py: Python<'py>, key: &str) -> PyResult<bool> {
        // TODO
        let dict = self.get_dict(py)?;
        dict.contains(key)
    }

    #[pyo3(signature = (key, default=None))]
    fn get<'py>(
        &self,
        py: Python<'py>,
        key: &str,
        default: Option<Bound<'py, PyAny>>,
    ) -> PyResult<Bound<'py, PyAny>> {
        if self.get_dict(py)?.contains(key)? {
            self.get_dict(py)?.get_item(key)
        } else {
            Ok(default.into_pyobject(py)?)
        }
    }

    #[getter]
    fn format_version(&self) -> u8 {
        match &self.inner {
            EventFormatEnum::V3(_) => 3,
            // ...
        }
    }

    fn items<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyList>> {
        let dict = self.get_dict(py)?;
        let dict = dict.cast::<PyDict>()?;
        Ok(dict.items())
    }

    fn keys<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyList>> {
        let dict = self.get_dict(py)?;
        let dict = dict.cast::<PyDict>()?;
        Ok(dict.keys())
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

        assert_eq!(&*event.common_fields.type_, "m.room.create");

        assert_eq!(
            event.common_fields.room_id.as_deref(),
            Some("!qVoJSympOqdUQRUfiC:localhost:8800")
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
