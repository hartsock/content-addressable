//! Python (PyO3) bindings for the `content-addressable` core crate.
//!
//! This crate is the **telescope, not the sky**: it exposes the same
//! content-addressing primitives the Rust core provides — BLAKE3 + CIDv1 over
//! canonical dag-cbor — to Python, sharing the exact same Rust core so a
//! `ContentId` computed in Python is byte-for-byte the one Rust would compute.
//!
//! The public surface (module `content_addressable`):
//!
//! - [`ContentId`] — a self-certifying identity wrapping a CIDv1.
//! - [`to_canonical_dagcbor`] / [`from_canonical_dagcbor`] — the canonical
//!   dag-cbor codec, applied to native Python values.
//! - [`content_id`] — `ContentId.from_canonical_bytes(to_canonical_dagcbor(x))`.
//!
//! Canonicalization and hashing are delegated to the core crate; the only work
//! done here is translating Python values to/from the serde data model (via
//! `pythonize`) and mapping core errors to Python exceptions.

use ::content_addressable::{canonical, ContentId as CoreContentId};
use ipld_core::ipld::Ipld;
use pyo3::exceptions::{PyTypeError, PyValueError};
use pyo3::prelude::*;
use pyo3::types::{PyBytes, PyDict, PyList};
use pyo3::IntoPyObjectExt;
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};

/// The self-certifying identity of a value: a CIDv1 (dag-cbor codec `0x71`,
/// BLAKE3 multihash `0x1e`) computed from canonical bytes.
///
/// A `ContentId` is derived from the data itself, so it *is* a proof of
/// integrity. Construct one from already-canonical bytes via
/// [`ContentId.from_canonical_bytes`], or obtain one for a Python value via the
/// module-level [`content_id`] helper.
#[pyclass(
    module = "content_addressable",
    name = "ContentId",
    frozen,
    from_py_object
)]
#[derive(Clone)]
struct PyContentId {
    inner: CoreContentId,
}

#[pymethods]
impl PyContentId {
    /// Compute the content id of already-canonical dag-cbor bytes.
    ///
    /// This is the core primitive: it hashes the given bytes with BLAKE3 and
    /// wraps the digest in a CIDv1. It does NOT re-canonicalize — the input is
    /// assumed to already be canonical dag-cbor (typically the output of
    /// [`to_canonical_dagcbor`]).
    #[staticmethod]
    fn from_canonical_bytes(data: &[u8]) -> Self {
        PyContentId {
            inner: CoreContentId::from_canonical_bytes(data),
        }
    }

    /// Parse a `ContentId` from its canonical CID binary form.
    ///
    /// Raises `ValueError` if the bytes are not a valid CID.
    #[staticmethod]
    fn from_bytes(cid_bytes: &[u8]) -> PyResult<Self> {
        CoreContentId::from_bytes(cid_bytes)
            .map(|inner| PyContentId { inner })
            .map_err(|e| PyValueError::new_err(e.to_string()))
    }

    /// Parse a `ContentId` from its multibase CID string form.
    ///
    /// Raises `ValueError` if the string is not a valid CID.
    #[staticmethod]
    fn parse(s: &str) -> PyResult<Self> {
        s.parse::<CoreContentId>()
            .map(|inner| PyContentId { inner })
            .map_err(|e| PyValueError::new_err(e.to_string()))
    }

    /// Encode this id as its canonical CID binary form (`bytes`).
    fn to_bytes<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new(py, &self.inner.to_bytes())
    }

    fn __str__(&self) -> String {
        self.inner.to_string()
    }

    fn __repr__(&self) -> String {
        format!("ContentId('{}')", self.inner)
    }

    fn __eq__(&self, other: &Self) -> bool {
        self.inner == other.inner
    }

    fn __ne__(&self, other: &Self) -> bool {
        self.inner != other.inner
    }

    fn __hash__(&self) -> u64 {
        // Hash the canonical CID bytes so equal ids hash equal, matching
        // __eq__. (CoreContentId is Hash, but its derive hashes the inner Cid;
        // hashing the stable byte form is equivalent and explicit.)
        let mut hasher = DefaultHasher::new();
        self.inner.to_bytes().hash(&mut hasher);
        hasher.finish()
    }
}

/// Encode a native Python value to its canonical dag-cbor bytes.
///
/// Accepts the dag-cbor-representable Python types: `dict`, `list`/`tuple`,
/// `int`, `str`, `bytes`/`bytearray`, `bool`, `None`, and `float` (per dag-cbor
/// float rules). Map keys are emitted in canonical order, so two semantically
/// equal dicts always produce identical bytes regardless of insertion order.
///
/// Raises `ValueError` if the value cannot be represented as canonical
/// dag-cbor; raises `TypeError` if it contains an unsupported Python type.
#[pyfunction]
fn to_canonical_dagcbor<'py>(
    py: Python<'py>,
    obj: &Bound<'py, PyAny>,
) -> PyResult<Bound<'py, PyBytes>> {
    // Python value -> serde Ipld value. Type mismatches (e.g. a set, a custom
    // object) surface here.
    let value: Ipld = pythonize::depythonize(obj)
        .map_err(|e| PyTypeError::new_err(format!("value is not dag-cbor representable: {e}")))?;
    // serde Ipld value -> canonical dag-cbor bytes (delegated to the core
    // crate's codec so Python and Rust agree byte-for-byte).
    let bytes = canonical::to_canonical_dagcbor(&value)
        .map_err(|e| PyValueError::new_err(e.to_string()))?;
    Ok(PyBytes::new(py, &bytes))
}

/// Convert a serde [`Ipld`] value into a native Python object.
///
/// This is done by hand rather than via `pythonize` because dag-cbor integers
/// are `i128` (`Ipld::Integer`). When this binding was bootstrapped on
/// `pythonize` 0.26 the serializer had no `serialize_i128`, so a full-width
/// integer could not survive the decode path. As of `pythonize` 0.29
/// (re-checked 2026-06-25) the serializer *does* implement `serialize_i128`,
/// so a `pythonize`-based decode would now round-trip `i128`. The manual
/// converter is retained deliberately: it is the decode contract this crate
/// has always shipped, and a security bump must not change emitted Python
/// values. Switching to `pythonize::pythonize` is a separate, behavior-review
/// follow-up — not part of this lockstep version bump.
///
/// Python ints are arbitrary precision, so the mapping is lossless:
///
/// - `Null` -> `None`, `Bool` -> `bool`, `Float` -> `float`, `String` -> `str`
/// - `Integer(i128)` -> `int` (full width, no overflow)
/// - `Bytes` -> `bytes`
/// - `List` -> `list`, `Map` -> `dict` (string keys)
/// - `Link(cid)` -> a [`ContentId`] (an IPLD tag-42 link becomes a real id)
fn ipld_to_py<'py>(py: Python<'py>, value: &Ipld) -> PyResult<Bound<'py, PyAny>> {
    match value {
        Ipld::Null => Ok(py.None().into_bound(py)),
        Ipld::Bool(b) => b.into_bound_py_any(py),
        Ipld::Integer(i) => i.into_bound_py_any(py),
        Ipld::Float(f) => f.into_bound_py_any(py),
        Ipld::String(s) => s.into_bound_py_any(py),
        Ipld::Bytes(b) => Ok(PyBytes::new(py, b).into_any()),
        Ipld::List(items) => {
            let list = PyList::empty(py);
            for item in items {
                list.append(ipld_to_py(py, item)?)?;
            }
            Ok(list.into_any())
        }
        Ipld::Map(map) => {
            let dict = PyDict::new(py);
            for (k, v) in map {
                dict.set_item(k, ipld_to_py(py, v)?)?;
            }
            Ok(dict.into_any())
        }
        Ipld::Link(cid) => {
            let id = PyContentId {
                inner: CoreContentId::from(*cid),
            };
            id.into_bound_py_any(py)
        }
    }
}

/// Decode canonical dag-cbor bytes back into a native Python value.
///
/// Inverse of [`to_canonical_dagcbor`]. Raises `ValueError` if the bytes are
/// not valid canonical dag-cbor.
#[pyfunction]
fn from_canonical_dagcbor<'py>(py: Python<'py>, data: &[u8]) -> PyResult<Bound<'py, PyAny>> {
    // dag-cbor bytes -> serde Ipld value.
    let value: Ipld = canonical::from_canonical_dagcbor(data)
        .map_err(|e| PyValueError::new_err(e.to_string()))?;
    // serde Ipld value -> Python object via the hand-written converter (the
    // crate's shipped decode contract; see `ipld_to_py` for why it is kept even
    // though pythonize 0.29 can now serialize i128).
    ipld_to_py(py, &value)
}

/// Compute the [`ContentId`] of a native Python value.
///
/// Equivalent to
/// `ContentId.from_canonical_bytes(to_canonical_dagcbor(obj))`: the value is
/// canonicalized to dag-cbor, then hashed into a CIDv1.
#[pyfunction]
fn content_id(py: Python<'_>, obj: &Bound<'_, PyAny>) -> PyResult<PyContentId> {
    let bytes = to_canonical_dagcbor(py, obj)?;
    Ok(PyContentId {
        inner: CoreContentId::from_canonical_bytes(bytes.as_bytes()),
    })
}

/// content_addressable — data that carries its own proof of integrity.
///
/// IPLD-native content addressing for Python: BLAKE3 + CIDv1 over canonical
/// dag-cbor, backed by the Rust `content-addressable` crate. A `ContentId`
/// computed here is identical to the one the Rust core computes for the same
/// canonical bytes.
///
/// This doc comment becomes the module's `__doc__`. PyO3 auto-populates
/// `__all__` from the `add_class` / `add_function` calls below, so it is NOT
/// set by hand (doing so collides with the auto-maintained index and would
/// duplicate the entries).
#[pymodule]
fn content_addressable(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<PyContentId>()?;
    m.add_function(wrap_pyfunction!(to_canonical_dagcbor, m)?)?;
    m.add_function(wrap_pyfunction!(from_canonical_dagcbor, m)?)?;
    m.add_function(wrap_pyfunction!(content_id, m)?)?;
    Ok(())
}
