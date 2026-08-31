//! Deserialize any `serde::Deserialize` type from env-var-shaped
//! `(key, value)` pairs.
//!
//! Rules:
//! - Only keys starting with `<PREFIX>_` are considered; the prefix is
//!   matched case-insensitively and stripped.
//! - Groups are separated by DOUBLE underscore `__`; single underscores
//!   inside a segment are kept verbatim (`TUN__IOURING__SQPOLL_IDLE_TIME`
//!   -> `tun.iouring.sqpoll_idle_time`).
//! - Segments are lowercased after splitting.
//! - An empty string value means "unset" and is skipped.
//! - Lists use `__0__`, `__1__`, ... index notation: indices must be
//!   numeric and contiguous from 0.

use std::collections::{BTreeMap, btree_map};
use std::fmt::{self, Display};
use std::str::FromStr;

use serde::de::{self, DeserializeOwned, DeserializeSeed, IntoDeserializer, Visitor};

/// Error type for env tree deserialization.
#[derive(Debug, Clone, PartialEq)]
pub struct Error(String);

impl Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for Error {}

impl de::Error for Error {
    fn custom<T: Display>(msg: T) -> Self {
        Error(msg.to_string())
    }
}

/// Tree built from the split env keys. A node may hold a scalar value, child
/// nodes, or both (e.g. `FOO=1` and `FOO__BAR=2`).
#[derive(Debug, Default)]
struct Node {
    value: Option<String>,
    children: BTreeMap<String, Node>,
}

fn build_tree(vars: impl IntoIterator<Item = (String, String)>, prefix: &str) -> Node {
    let prefix = format!("{}_", prefix.to_ascii_uppercase());
    let mut root = Node::default();
    for (key, value) in vars {
        let key = key.to_ascii_uppercase();
        let Some(rest) = key.strip_prefix(&prefix) else {
            continue;
        };
        // Empty value means "unset".
        if rest.is_empty() || value.is_empty() {
            continue;
        }
        let mut node = &mut root;
        for seg in rest.split("__").filter(|s| !s.is_empty()) {
            node = node.children.entry(seg.to_ascii_lowercase()).or_default();
        }
        node.value = Some(value);
    }
    root
}

/// Deserialize `T` from `(key, value)` pairs whose keys start with
/// `prefix` + `_`.
pub fn from_iter_with_prefix<T, I>(vars: I, prefix: &str) -> Result<T, Error>
where
    T: DeserializeOwned,
    I: IntoIterator<Item = (String, String)>,
{
    let root = build_tree(vars, prefix);
    T::deserialize(NodeDeserializer {
        node: &root,
        path: String::new(),
    })
}

/// Deserialize `T` from the process environment.
pub fn from_env_with_prefix<T: DeserializeOwned>(prefix: &str) -> Result<T, Error> {
    from_iter_with_prefix(std::env::vars(), prefix)
}

struct NodeDeserializer<'a> {
    node: &'a Node,
    /// Dotted path from the root, for error messages.
    path: String,
}

impl<'a> NodeDeserializer<'a> {
    fn value(&self) -> Result<&'a str, Error> {
        self.node
            .value
            .as_deref()
            .ok_or_else(|| Error(format!("missing value for '{}'", self.path)))
    }

    fn parse<T: FromStr>(&self, expected: &str) -> Result<T, Error>
    where
        T::Err: Display,
    {
        let raw = self.value()?;
        raw.parse().map_err(|e| {
            Error(format!(
                "invalid {expected} for '{}': '{raw}' ({e})",
                self.path
            ))
        })
    }

    fn unsupported(&self, what: &str) -> Error {
        Error(format!("{what} not supported (at '{}')", self.path))
    }
}

macro_rules! parse_scalars {
    ($($method:ident => $visit:ident($ty:ty) as $name:literal;)*) => {
        $(fn $method<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, Error> {
            visitor.$visit(self.parse::<$ty>($name)?)
        })*
    };
}

impl<'de, 'a> de::Deserializer<'de> for NodeDeserializer<'a> {
    type Error = Error;

    /// A leaf is a string, a group is a map. Needed for
    /// `#[serde(flatten)]` catch-alls, which buffer through
    /// `deserialize_any`.
    fn deserialize_any<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, Error> {
        if !self.node.children.is_empty() {
            self.deserialize_map(visitor)
        } else if let Some(value) = self.node.value.as_deref() {
            visitor.visit_str(value)
        } else {
            visitor.visit_unit()
        }
    }

    parse_scalars! {
        deserialize_bool => visit_bool(bool) as "bool";
        deserialize_i8 => visit_i8(i8) as "i8";
        deserialize_i16 => visit_i16(i16) as "i16";
        deserialize_i32 => visit_i32(i32) as "i32";
        deserialize_i64 => visit_i64(i64) as "i64";
        deserialize_i128 => visit_i128(i128) as "i128";
        deserialize_u8 => visit_u8(u8) as "u8";
        deserialize_u16 => visit_u16(u16) as "u16";
        deserialize_u32 => visit_u32(u32) as "u32";
        deserialize_u64 => visit_u64(u64) as "u64";
        deserialize_u128 => visit_u128(u128) as "u128";
        deserialize_f32 => visit_f32(f32) as "f32";
        deserialize_f64 => visit_f64(f64) as "f64";
    }

    fn deserialize_char<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, Error> {
        visitor.visit_str(self.value()?)
    }

    fn deserialize_str<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, Error> {
        visitor.visit_str(self.value()?)
    }

    fn deserialize_string<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, Error> {
        self.deserialize_str(visitor)
    }

    fn deserialize_identifier<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, Error> {
        self.deserialize_str(visitor)
    }

    fn deserialize_bytes<V: Visitor<'de>>(self, _visitor: V) -> Result<V::Value, Error> {
        Err(self.unsupported("bytes"))
    }

    fn deserialize_byte_buf<V: Visitor<'de>>(self, _visitor: V) -> Result<V::Value, Error> {
        Err(self.unsupported("bytes"))
    }

    /// The node exists at all only because some var under it was set, so an
    /// existing node is always `Some`.
    fn deserialize_option<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, Error> {
        visitor.visit_some(self)
    }

    fn deserialize_unit<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, Error> {
        visitor.visit_unit()
    }

    fn deserialize_unit_struct<V: Visitor<'de>>(
        self,
        _name: &'static str,
        visitor: V,
    ) -> Result<V::Value, Error> {
        visitor.visit_unit()
    }

    fn deserialize_newtype_struct<V: Visitor<'de>>(
        self,
        _name: &'static str,
        visitor: V,
    ) -> Result<V::Value, Error> {
        visitor.visit_newtype_struct(self)
    }

    /// Lists use `__0__`, `__1__`, ... index notation: every child key must
    /// be numeric, indices must be contiguous from 0, elements are visited
    /// in numeric order.
    fn deserialize_seq<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, Error> {
        if self.node.children.is_empty() {
            if self.node.value.is_some() {
                return Err(Error(format!(
                    "expected a list at '{path}' (use {path}.0, {path}.1, ... index \
                     notation, i.e. __0__ in env var names), found a scalar value",
                    path = self.path
                )));
            }
            // No value and no children: only reachable for an empty root.
            return visitor.visit_seq(NodeSeqAccess {
                iter: Vec::new().into_iter(),
                path: self.path,
            });
        }
        let mut indexed = Vec::with_capacity(self.node.children.len());
        for (key, child) in &self.node.children {
            let idx: usize = key.parse().map_err(|_| {
                Error(format!(
                    "expected a numeric list index under '{}', found key '{key}' \
                     (lists use __0__, __1__, ... notation)",
                    self.path
                ))
            })?;
            indexed.push((idx, child));
        }
        // BTreeMap ordering is lexicographic ("10" < "2"); order numerically.
        indexed.sort_unstable_by_key(|(idx, _)| *idx);
        for (pos, (idx, _)) in indexed.iter().enumerate() {
            if *idx != pos {
                return Err(Error(format!(
                    "list indices under '{}' must be contiguous from 0: \
                     expected index {pos}, found {idx}",
                    self.path
                )));
            }
        }
        visitor.visit_seq(NodeSeqAccess {
            iter: indexed.into_iter(),
            path: self.path,
        })
    }

    fn deserialize_tuple<V: Visitor<'de>>(
        self,
        _len: usize,
        _visitor: V,
    ) -> Result<V::Value, Error> {
        Err(self.unsupported("tuples"))
    }

    fn deserialize_tuple_struct<V: Visitor<'de>>(
        self,
        _name: &'static str,
        _len: usize,
        _visitor: V,
    ) -> Result<V::Value, Error> {
        Err(self.unsupported("tuple structs"))
    }

    fn deserialize_map<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, Error> {
        visitor.visit_map(NodeMapAccess {
            iter: self.node.children.iter(),
            pending: None,
            path: self.path,
        })
    }

    fn deserialize_struct<V: Visitor<'de>>(
        self,
        _name: &'static str,
        _fields: &'static [&'static str],
        visitor: V,
    ) -> Result<V::Value, Error> {
        self.deserialize_map(visitor)
    }

    /// Unit variants only, from the leaf string.
    fn deserialize_enum<V: Visitor<'de>>(
        self,
        _name: &'static str,
        _variants: &'static [&'static str],
        visitor: V,
    ) -> Result<V::Value, Error> {
        visitor.visit_enum(self.value()?.to_owned().into_deserializer())
    }

    fn deserialize_ignored_any<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, Error> {
        self.deserialize_any(visitor)
    }
}

struct NodeMapAccess<'a> {
    iter: btree_map::Iter<'a, String, Node>,
    pending: Option<(&'a str, &'a Node)>,
    path: String,
}

impl<'de, 'a> de::MapAccess<'de> for NodeMapAccess<'a> {
    type Error = Error;

    fn next_key_seed<K: DeserializeSeed<'de>>(
        &mut self,
        seed: K,
    ) -> Result<Option<K::Value>, Error> {
        let Some((key, node)) = self.iter.next() else {
            return Ok(None);
        };
        self.pending = Some((key, node));
        seed.deserialize(key.to_owned().into_deserializer())
            .map(Some)
    }

    fn next_value_seed<V: DeserializeSeed<'de>>(&mut self, seed: V) -> Result<V::Value, Error> {
        let (key, node) = self
            .pending
            .take()
            .expect("next_value_seed called before next_key_seed");
        let path = if self.path.is_empty() {
            key.to_owned()
        } else {
            format!("{}.{key}", self.path)
        };
        seed.deserialize(NodeDeserializer { node, path })
    }
}

struct NodeSeqAccess<'a> {
    /// `(index, node)` pairs, already numerically sorted and gap-checked.
    iter: std::vec::IntoIter<(usize, &'a Node)>,
    path: String,
}

impl<'de, 'a> de::SeqAccess<'de> for NodeSeqAccess<'a> {
    type Error = Error;

    fn next_element_seed<T: DeserializeSeed<'de>>(
        &mut self,
        seed: T,
    ) -> Result<Option<T::Value>, Error> {
        let Some((idx, node)) = self.iter.next() else {
            return Ok(None);
        };
        let path = if self.path.is_empty() {
            idx.to_string()
        } else {
            format!("{}.{idx}", self.path)
        };
        seed.deserialize(NodeDeserializer { node, path }).map(Some)
    }

    fn size_hint(&self) -> Option<usize> {
        Some(self.iter.len())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::Deserialize;
    use std::collections::HashMap;

    fn v(pairs: &[(&str, &str)]) -> Vec<(String, String)> {
        pairs
            .iter()
            .map(|(k, val)| (k.to_string(), val.to_string()))
            .collect()
    }

    #[derive(Deserialize, Default, Debug, PartialEq)]
    #[serde(default)]
    struct Keepalive {
        interval: Option<String>,
        timeout: Option<String>,
    }

    #[derive(Deserialize, Default, Debug, PartialEq)]
    #[serde(default)]
    struct Iouring {
        enabled: Option<bool>,
        entry_count: Option<u32>,
    }

    #[derive(Deserialize, Default, Debug, PartialEq)]
    #[serde(default)]
    struct Tun {
        name: Option<String>,
        iouring: Iouring,
    }

    #[derive(Deserialize, Default, Debug, PartialEq)]
    #[serde(rename_all = "lowercase")]
    enum Mode {
        #[default]
        Tcp,
        Udp,
    }

    #[derive(Deserialize, Default, Debug, PartialEq)]
    #[serde(default)]
    struct Entry {
        server: Option<String>,
        cipher: Option<String>,
    }

    #[derive(Deserialize, Default, Debug, PartialEq)]
    #[serde(default)]
    struct Connect {
        mode: Option<Mode>,
        servers: Option<Vec<Entry>>,
    }

    #[derive(Deserialize, Default, Debug, PartialEq)]
    #[serde(default)]
    struct Cfg {
        count: Option<u32>,
        keepalive: Keepalive,
        tun: Tun,
        connect: Connect,
        #[serde(flatten)]
        unknowns: HashMap<String, serde_json::Value>,
    }

    #[test]
    fn scalars_groups_and_inner_underscores() {
        let cfg: Cfg = from_iter_with_prefix(
            v(&[
                ("LW_CLIENT_COUNT", "1024"),
                ("LW_CLIENT_KEEPALIVE__INTERVAL", "10s"),
                ("LW_CLIENT_TUN__IOURING__ENTRY_COUNT", "2048"),
                ("LW_CLIENT_TUN__IOURING__ENABLED", "true"),
            ]),
            "LW_CLIENT",
        )
        .unwrap();
        assert_eq!(cfg.count, Some(1024));
        assert_eq!(cfg.keepalive.interval.as_deref(), Some("10s"));
        assert_eq!(cfg.tun.iouring.entry_count, Some(2048));
        assert_eq!(cfg.tun.iouring.enabled, Some(true));
    }

    #[test]
    fn empty_value_is_unset_and_enums_parse() {
        let cfg: Cfg = from_iter_with_prefix(
            v(&[
                ("LW_CLIENT_KEEPALIVE__TIMEOUT", ""),
                ("LW_CLIENT_CONNECT__MODE", "udp"),
            ]),
            "LW_CLIENT",
        )
        .unwrap();
        assert_eq!(cfg.keepalive.timeout, None);
        assert_eq!(cfg.connect.mode, Some(Mode::Udp));
    }

    #[test]
    fn lists_via_index_notation() {
        let cfg: Cfg = from_iter_with_prefix(
            v(&[
                ("LW_CLIENT_CONNECT__SERVERS__0__SERVER", "a:1"),
                ("LW_CLIENT_CONNECT__SERVERS__1__SERVER", "b:2"),
                ("LW_CLIENT_CONNECT__SERVERS__1__CIPHER", "chacha20"),
            ]),
            "LW_CLIENT",
        )
        .unwrap();
        let servers = cfg.connect.servers.unwrap();
        assert_eq!(servers.len(), 2);
        assert_eq!(servers[0].server.as_deref(), Some("a:1"));
        assert_eq!(servers[0].cipher, None);
        assert_eq!(servers[1].cipher.as_deref(), Some("chacha20"));
    }

    #[test]
    fn list_index_gap_is_error() {
        let err = from_iter_with_prefix::<Cfg, _>(
            v(&[
                ("LW_CLIENT_CONNECT__SERVERS__0__SERVER", "a:1"),
                ("LW_CLIENT_CONNECT__SERVERS__2__SERVER", "c:3"),
            ]),
            "LW_CLIENT",
        )
        .unwrap_err();
        assert!(err.to_string().contains("contiguous"), "{err}");
    }

    #[test]
    fn wrong_type_gives_readable_error() {
        let err = from_iter_with_prefix::<Cfg, _>(v(&[("LW_CLIENT_COUNT", "abc")]), "LW_CLIENT")
            .unwrap_err();
        assert!(err.to_string().contains("invalid u32 for 'count'"), "{err}");
    }

    #[test]
    fn unknown_top_level_key_lands_in_flatten() {
        let cfg: Cfg =
            from_iter_with_prefix(v(&[("LW_CLIENT_MYSTERY", "42")]), "LW_CLIENT").unwrap();
        assert_eq!(
            cfg.unknowns.get("mystery"),
            Some(&serde_json::Value::String("42".into()))
        );
    }
}
