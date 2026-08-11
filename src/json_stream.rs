//! Streaming JSON array and document output.
//!
//! `serde_json::to_writer`/`to_writer_pretty` already stream to a `Write`
//! rather than building a `String`, but only if the `Serialize` tree itself
//! never materializes an intermediate collection along the way. [`SeqStream`]
//! lets a JSON array field be produced by walking a slice/iterator
//! element-by-element as the writer asks for it, instead of collecting a
//! `Vec` of projected values up front. Embedding a [`SeqStream`]-typed field
//! inside a `#[derive(Serialize)]` struct works with no special-casing,
//! since `serde_json`'s serializer calls straight through to the field's
//! `Serialize::serialize` as it walks the struct.

use anyhow::Result;
use serde::ser::SerializeSeq;
use serde::{Serialize, Serializer};
use std::cell::RefCell;
use std::io::Write;

/// Streams an iterator's items into a JSON array, one element at a time,
/// without collecting them into a `Vec` first. Works with any iterator chain
/// (`flat_map`, `filter`, `map`, ...) since the wrapper is generic over the
/// iterator type rather than trying to name it explicitly at each call site.
pub struct IterStream<I> {
    iter: RefCell<Option<I>>,
}

impl<I> IterStream<I>
where
    I: Iterator,
    I::Item: Serialize,
{
    pub fn new(iter: I) -> Self {
        Self {
            iter: RefCell::new(Some(iter)),
        }
    }
}

impl<I> Serialize for IterStream<I>
where
    I: Iterator,
    I::Item: Serialize,
{
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let iter = self
            .iter
            .borrow_mut()
            .take()
            .expect("IterStream must only be serialized once");
        let (lower, upper) = iter.size_hint();
        let mut seq = serializer.serialize_seq(upper.or(Some(lower)))?;
        for item in iter {
            seq.serialize_element(&item)?;
        }
        seq.end()
    }
}

/// Stream an iterator as a JSON array without collecting it into a `Vec`.
pub fn stream_iter<I>(iter: I) -> IterStream<I>
where
    I: Iterator,
    I::Item: Serialize,
{
    IterStream::new(iter)
}

/// Stream `items` as a JSON array, projecting each element through `project`
/// without collecting the projected values into a `Vec` first.
pub fn stream_seq<'a, T, U>(
    items: &'a [T],
    project: impl Fn(&'a T) -> U + 'a,
) -> IterStream<impl Iterator<Item = U> + 'a>
where
    U: Serialize,
{
    stream_iter(items.iter().map(project))
}

/// Write `value` as JSON to `writer`, followed by a trailing newline, then
/// flush. Streams directly into the writer instead of building a `String`.
pub fn write_json<W: Write, T: Serialize>(mut writer: W, value: &T, pretty: bool) -> Result<()> {
    if pretty {
        serde_json::to_writer_pretty(&mut writer, value)?;
    } else {
        serde_json::to_writer(&mut writer, value)?;
    }
    writer.write_all(b"\n")?;
    writer.flush()?;
    Ok(())
}

/// Write `value` to stdout as JSON (pretty or compact), followed by a
/// trailing newline, then flush.
pub fn write_stdout_json<T: Serialize>(value: &T, pretty: bool) -> Result<()> {
    let stdout = std::io::stdout();
    let lock = stdout.lock();
    write_json(lock, value, pretty)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seq_stream_matches_plain_vec_serialization() {
        let items = vec![1, 2, 3, 4];
        let streamed = stream_seq(&items, |value| value * 2);
        let streamed_json = serde_json::to_string(&streamed).expect("serialize stream");
        let doubled: Vec<i32> = items.iter().map(|value| value * 2).collect();
        let plain_json = serde_json::to_string(&doubled).expect("serialize vec");
        assert_eq!(streamed_json, plain_json);
    }

    #[test]
    fn seq_stream_embeds_in_a_struct_field() {
        #[derive(Serialize)]
        struct Doc<'a, S: Serialize> {
            name: &'a str,
            items: S,
        }

        let items = vec![10, 20];
        let doc = Doc {
            name: "example",
            items: stream_seq(&items, |value| *value + 1),
        };
        let json = serde_json::to_string(&doc).expect("serialize doc");
        assert_eq!(json, r#"{"name":"example","items":[11,21]}"#);
    }

    #[test]
    fn write_json_appends_trailing_newline() {
        let mut buffer = Vec::new();
        write_json(&mut buffer, &serde_json::json!({"a": 1}), false).expect("write json");
        assert_eq!(buffer, b"{\"a\":1}\n");
    }
}
