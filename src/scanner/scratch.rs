//! Worker-owned, bounded scratch buffers reused across scan calls on the same
//! thread.
//!
//! Each buffer is taken out of thread-local storage for the duration of one
//! use and returned afterward, rather than borrowed in place: a scan call
//! that (directly or through nested format/archive handling) re-enters the
//! same scan path on the same thread simply finds its slot empty and
//! allocates a fresh buffer for that inner call, instead of panicking on a
//! `RefCell` double-borrow. No global pool -- each OS thread owns its own
//! slot exclusively, so there is no cross-thread synchronization.
//!
//! A buffer whose capacity has grown beyond [`MAX_SCRATCH_CAPACITY`] (e.g.
//! from a single unusually large read) is dropped instead of being kept for
//! reuse, so an attacker-triggered oversized allocation isn't pinned in
//! memory for the rest of the process.

use std::cell::RefCell;
use std::thread::LocalKey;

use crate::scanner::session::STREAM_CHUNK_BYTES;

const MAX_SCRATCH_CAPACITY: usize = 8 * STREAM_CHUNK_BYTES;

thread_local! {
    static READ_BUF: RefCell<Vec<u8>> = const { RefCell::new(Vec::new()) };
    static WINDOW_BUF: RefCell<Vec<u8>> = const { RefCell::new(Vec::new()) };
    static NORMALIZE_BUF: RefCell<String> = const { RefCell::new(String::new()) };
}

fn take_vec(cell: &'static LocalKey<RefCell<Vec<u8>>>) -> Vec<u8> {
    cell.with(|slot| {
        let mut taken = std::mem::take(&mut *slot.borrow_mut());
        if taken.capacity() > MAX_SCRATCH_CAPACITY {
            taken = Vec::new();
        } else {
            taken.clear();
        }
        taken
    })
}

fn return_vec(cell: &'static LocalKey<RefCell<Vec<u8>>>, buf: Vec<u8>) {
    if buf.capacity() <= MAX_SCRATCH_CAPACITY {
        cell.with(|slot| *slot.borrow_mut() = buf);
    }
}

/// A raw I/O read destination buffer, at least `min_len` bytes long and
/// ready to read into directly (`Read::read(&mut buf)`).
///
/// Deliberately does not clear the buffer's existing length/content: callers
/// only ever consult the `[..count]` prefix that `Read::read` actually wrote
/// on each call, never anything past it, so old bytes left in the tail are
/// never observed. Skipping the clear means only the first use per thread
/// pays a real fill cost when growing to `min_len`; every later reuse finds
/// the buffer already at least that long and the resize is a no-op, instead
/// of re-zero-filling the whole buffer on every call.
pub(crate) fn take_read_buf(min_len: usize) -> Vec<u8> {
    READ_BUF.with(|slot| {
        let mut taken = std::mem::take(&mut *slot.borrow_mut());
        if taken.capacity() > MAX_SCRATCH_CAPACITY {
            taken = Vec::new();
        }
        if taken.len() < min_len {
            taken.resize(min_len, 0);
        }
        taken
    })
}

pub(crate) fn return_read_buf(buf: Vec<u8>) {
    return_vec(&READ_BUF, buf)
}

/// The `carry`+new-bytes concatenation buffer used ahead of normalization.
pub(crate) fn take_window_buf() -> Vec<u8> {
    take_vec(&WINDOW_BUF)
}

pub(crate) fn return_window_buf(buf: Vec<u8>) {
    return_vec(&WINDOW_BUF, buf)
}

/// The normalized-text output buffer. Content is cleared (not just truncated
/// to length) before reuse: this buffer transiently holds literal
/// secret-shaped bytes whenever a signature matches within it, so leaving old
/// contents live in unused capacity across files is undesirable even though
/// it isn't itself a data leak (the capacity is never read without first
/// being written).
pub(crate) fn take_normalize_buf() -> String {
    NORMALIZE_BUF.with(|slot| {
        let mut taken = std::mem::take(&mut *slot.borrow_mut());
        if taken.capacity() > MAX_SCRATCH_CAPACITY {
            taken = String::new();
        } else {
            taken.clear();
        }
        taken
    })
}

pub(crate) fn return_normalize_buf(buf: String) {
    if buf.capacity() <= MAX_SCRATCH_CAPACITY {
        NORMALIZE_BUF.with(|slot| *slot.borrow_mut() = buf);
    }
}
