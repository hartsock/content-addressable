//! Python (PyO3) bindings for the `content-addressable` core crate.
//!
//! This crate is the **telescope, not the sky**: it exposes the same
//! content-addressing primitives the Rust core provides — BLAKE3 + CIDv1 over
//! canonical dag-cbor — to Python, sharing the exact same Rust core so a
//! `ContentId` computed in Python is byte-for-byte the one Rust would compute.
//!
//! The public surface (module `content_addressable`):
//!
//! - [`ContentId`] — a self-certifying identity wrapping a CIDv1. Its frozen
//!   presentation forms (issue #6) are `str(id)` (base32-lower text),
//!   `to_bytes()` (CID binary envelope), `digest_bytes()` (raw 32-byte BLAKE3
//!   hash), and `digest_hex()` (bare-digest-hex).
//! - [`RawContentId`] — the identity of an opaque byte string (the *raw*
//!   profile: CIDv1 raw `0x55` + BLAKE3 `0x1e`), sibling to `ContentId` (the
//!   dag-cbor profile) with the same presentation forms. The two never compare
//!   equal, even on identical digests — the codec is part of the identity
//!   (issue #84).
//! - [`to_canonical_dagcbor`] / [`from_canonical_dagcbor`] — the canonical
//!   dag-cbor codec, applied to native Python values.
//! - [`content_id`] — `ContentId.from_canonical_bytes(to_canonical_dagcbor(x))`.
//!
//! Canonicalization and hashing are delegated to the core crate; the only work
//! done here is translating Python values to/from the serde data model (via
//! `pythonize`) and mapping core errors to Python exceptions.

use ::content_addressable::{
    canonical, ContentId as CoreContentId, RawContentId as CoreRawContentId,
};
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

    /// Wrap an **already-computed** 32-byte BLAKE3 content digest as a
    /// `ContentId` — **without hashing it again**.
    ///
    /// This is an UNCHECKED escape hatch for BLAKE3-native upstreams that
    /// already hashed their content and hold only the 32-byte digest (a
    /// signature, an address), not the original canonical bytes. It wraps the
    /// digest directly (BLAKE3 multihash `0x1e` -> CIDv1 dag-cbor `0x71`); no
    /// BLAKE3 step runs.
    ///
    /// WARNING: the caller asserts `digest` is exactly BLAKE3 over the value's
    /// canonical dag-cbor bytes. This does NOT hash and does NOT canonicalize.
    /// A digest computed any other way produces a `ContentId` that names
    /// content nothing actually hashed. If you have the content bytes, use
    /// [`ContentId.from_canonical_bytes`] instead — it hashes them for you.
    ///
    /// Raises `ValueError` if `digest` is not exactly 32 bytes. (Unlike the
    /// Rust core's `[u8; 32]` argument, a Python `bytes` carries no
    /// compile-time length guarantee, so the length is validated here.)
    ///
    /// DEPRECATED (issue #84): this stamps the dag-cbor codec on a digest it
    /// cannot know came from dag-cbor. For a digest of opaque bytes use
    /// `RawContentId.from_blake3_digest` (the honest profile); when the digest
    /// is known to be over canonical dag-cbor, say so with
    /// `ContentId.from_dag_cbor_digest`. Behavior is unchanged; it will be
    /// removed in a future major version.
    #[staticmethod]
    fn from_blake3_content_digest(digest: &[u8]) -> PyResult<Self> {
        Self::from_dag_cbor_digest(digest)
    }

    /// Wrap an already-computed 32-byte BLAKE3 digest **of canonical dag-cbor
    /// bytes** as a `ContentId`, without hashing again. The name asserts the
    /// precondition; a digest of anything else mints an id whose dag-cbor codec
    /// is a lie — for opaque bytes use `RawContentId.from_blake3_digest`.
    /// Byte-identical to the deprecated `from_blake3_content_digest`.
    ///
    /// Raises `ValueError` if `digest` is not exactly 32 bytes.
    #[staticmethod]
    fn from_dag_cbor_digest(digest: &[u8]) -> PyResult<Self> {
        let arr: [u8; 32] = digest.try_into().map_err(|_| {
            PyValueError::new_err(format!(
                "BLAKE3 content digest must be exactly 32 bytes, got {}",
                digest.len()
            ))
        })?;
        Ok(PyContentId {
            inner: CoreContentId::from_dag_cbor_digest(arr),
        })
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
    ///
    /// This is the full CID **envelope** (version + codec + multihash header +
    /// digest), not the bare hash. Part of the frozen presentation contract
    /// (issue #6); mirrors the Rust core's `to_bytes`.
    fn to_bytes<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new(py, &self.inner.to_bytes())
    }

    /// The raw 32-byte BLAKE3 content digest (`bytes`) — the bare hash, with no
    /// CID envelope.
    ///
    /// This is the sovereign hash an adopter joins on across systems. The length
    /// is a frozen invariant (always 32 bytes). Mirrors the Rust core's
    /// `digest_bytes`; part of the frozen presentation contract (issue #6).
    fn digest_bytes<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new(py, &self.inner.digest_bytes())
    }

    /// Lowercase hex of the raw 32-byte BLAKE3 digest: 64 chars, no `0x`/
    /// multibase prefix (`str`).
    ///
    /// This is the **"bare-digest-hex"** convention — hex of `digest_bytes()`,
    /// *not* of the full CID. It is the shortest, hash-only "hex" form (e.g.
    /// kyln's `to_hex()`). For the full CID envelope as hex, hex-encode
    /// `to_bytes()` explicitly; this crate deliberately does not provide a
    /// `cid_hex()` (it would re-introduce the ambiguity this contract ends —
    /// see the Rust core docs). Mirrors the Rust core's `digest_hex`; part of
    /// the frozen presentation contract (issue #6).
    fn digest_hex(&self) -> String {
        self.inner.digest_hex()
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

/// The identity of an opaque byte string: a CIDv1 with the `raw` codec (`0x55`)
/// and a BLAKE3 multihash (`0x1e`) over the bytes themselves — the *raw*
/// profile, sibling to `ContentId` (the dag-cbor profile).
///
/// Use it for files, chunks, binaries, payloads: anything whose identity is
/// "these bytes", not "this value". `RawContentId.from_content(b)` hashes bytes
/// you hold; `RawContentId.from_blake3_digest(d)` wraps a digest you already
/// have (no re-hash) — byte-identical to kyln's raw CIDs and to any bare
/// `blake3` digest of the same bytes.
///
/// The presentation forms are the same as `ContentId`'s: `str(id)` (base32-lower
/// text), `to_bytes()` (CID envelope), `digest_bytes()` / `digest_hex()` (bare
/// 32-byte digest). A `RawContentId` and a `ContentId` are **never equal**, even
/// when their digests are identical: the codec is part of the identity (issue
/// #84, law 6). Comparing one to the other is `False`, and each class's parsers
/// reject the other's CIDs.
#[pyclass(
    module = "content_addressable",
    name = "RawContentId",
    frozen,
    from_py_object
)]
#[derive(Clone)]
struct PyRawContentId {
    inner: CoreRawContentId,
}

#[pymethods]
impl PyRawContentId {
    /// The identity of `content`: CIDv1(raw, BLAKE3(content)). Hashes the bytes.
    #[staticmethod]
    fn from_content(content: &[u8]) -> Self {
        PyRawContentId {
            inner: CoreRawContentId::from_content(content),
        }
    }

    /// Wrap an already-computed 32-byte BLAKE3 digest of some content as a
    /// `RawContentId`, without hashing again. The caller asserts the digest is
    /// BLAKE3 over the content they mean; verify with `verify(content)` when
    /// the bytes are available.
    ///
    /// Raises `ValueError` if `digest` is not exactly 32 bytes.
    #[staticmethod]
    fn from_blake3_digest(digest: &[u8]) -> PyResult<Self> {
        let arr: [u8; 32] = digest.try_into().map_err(|_| {
            PyValueError::new_err(format!(
                "BLAKE3 digest must be exactly 32 bytes, got {}",
                digest.len()
            ))
        })?;
        Ok(PyRawContentId {
            inner: CoreRawContentId::from_blake3_digest(arr),
        })
    }

    /// Parse a `RawContentId` from its CID binary form. Raises `ValueError` if
    /// the bytes are not a CID, or are a CID of another profile (including a
    /// dag-cbor `ContentId`).
    #[staticmethod]
    fn from_bytes(cid_bytes: &[u8]) -> PyResult<Self> {
        CoreRawContentId::from_bytes(cid_bytes)
            .map(|inner| PyRawContentId { inner })
            .map_err(|e| PyValueError::new_err(e.to_string()))
    }

    /// Parse a `RawContentId` from its multibase CID string. Raises
    /// `ValueError` for a non-CID or a CID of another profile.
    #[staticmethod]
    fn parse(s: &str) -> PyResult<Self> {
        s.parse::<CoreRawContentId>()
            .map(|inner| PyRawContentId { inner })
            .map_err(|e| PyValueError::new_err(e.to_string()))
    }

    /// `True` iff `content` hashes to this id.
    fn verify(&self, content: &[u8]) -> bool {
        self.inner.verify(content)
    }

    /// The full CID binary envelope (`bytes`).
    fn to_bytes<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new(py, &self.inner.to_bytes())
    }

    /// The raw 32-byte BLAKE3 digest (`bytes`), no envelope.
    fn digest_bytes<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new(py, &self.inner.digest_bytes())
    }

    /// Lowercase hex of the raw 32-byte digest: 64 chars, no prefix. A digest
    /// accessor, not an identity — it is identical for a `ContentId` over the
    /// same digest and must never be compared as if it were the id.
    fn digest_hex(&self) -> String {
        self.inner.digest_hex()
    }

    fn __str__(&self) -> String {
        self.inner.to_string()
    }

    fn __repr__(&self) -> String {
        format!("RawContentId('{}')", self.inner)
    }

    fn __eq__(&self, other: &Self) -> bool {
        self.inner == other.inner
    }

    fn __ne__(&self, other: &Self) -> bool {
        self.inner != other.inner
    }

    fn __hash__(&self) -> u64 {
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
            // A decoded tag-42 link is an arbitrary CID — admit it only if it is
            // this crate's profile, else raise ValueError (never panic downstream).
            let inner =
                CoreContentId::try_from(*cid).map_err(|e| PyValueError::new_err(e.to_string()))?;
            let id = PyContentId { inner };
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
    m.add_class::<PyRawContentId>()?;
    m.add_function(wrap_pyfunction!(to_canonical_dagcbor, m)?)?;
    m.add_function(wrap_pyfunction!(from_canonical_dagcbor, m)?)?;
    m.add_function(wrap_pyfunction!(content_id, m)?)?;
    Ok(())
}
