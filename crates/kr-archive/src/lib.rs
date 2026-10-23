//! `kr-archive`: streaming DEFLATE (RFC 1951), gzip (RFC 1952) and tar
//! (ustar / pax / GNU) for OCI layer unpacking.
//!
//! The crate is pure: no syscalls, no unsafe, no dependencies. Everything is
//! push-based: callers feed arbitrary-sized input chunks and receive output
//! through a callback, so a layer is never buffered whole (memory use is a
//! 32 KiB window plus small headers).
//!
//! # Security contract for extraction
//!
//! * [`tar::sanitize`] lexically rejects absolute paths and `..` escapes and
//!   normalizes `./` and repeated slashes. It is purely lexical.
//! * **The runtime MUST ALSO guard symlink traversal at extraction time**
//!   (e.g. open every parent component with `O_NOFOLLOW`/`openat2` with
//!   `RESOLVE_BENEATH`). A layer can create `a -> /etc` and then a later entry
//!   `a/passwd`, which is lexically innocent. That is not this crate's job.
//! * Symlink and hardlink *targets* (`linkname`) are reported verbatim and
//!   are not sanitized; validate them against the rootfs when extracting.
//! * OCI whiteouts are exposed via [`tar::whiteout`]; the runtime applies them.
#![no_std]
#![forbid(unsafe_code)]

extern crate alloc;
#[cfg(test)]
extern crate std;

pub mod crc32;
pub mod gzip;
pub mod inflate;
pub mod tar;

use core::fmt;

/// Error type shared by all modules. `E` is the error type of the caller's
/// output callback (carried in [`Error::Sink`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error<E = ()> {
    /// The output callback failed.
    Sink(E),
    /// The decoder already failed; it cannot be reused without `reset`.
    Failed,
    /// Input ended in the middle of a stream/entry.
    Truncated,

    // --- inflate ---
    InvalidBlockType,
    StoredLenMismatch,
    InvalidCodeLengths,
    InvalidCodeLengthRepeat,
    OversubscribedCode,
    IncompleteCode,
    MissingEndOfBlock,
    InvalidCode,
    InvalidLengthSymbol,
    InvalidDistanceSymbol,
    DistanceTooFar,

    // --- gzip ---
    BadMagic,
    UnsupportedMethod,
    ReservedFlags,
    HeaderCrc,
    Crc32Mismatch,
    SizeMismatch,
    TrailingGarbage,

    // --- tar ---
    BadChecksum,
    BadNumber,
    BadPax,
    MetaTooLarge,
    UnsupportedType(u8),
    InvalidUtf8,
    SizeOverflow,

    // --- paths ---
    UnsafePath,
}

impl<E> fmt::Display for Error<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::UnsupportedType(t) => write!(f, "unsupported tar type flag {:#04x}", t),
            _ => f.write_str(self.name()),
        }
    }
}

impl<E> Error<E> {
    fn name(&self) -> &'static str {
        match self {
            Error::Sink(_) => "output sink failed",
            Error::Failed => "decoder previously failed",
            Error::Truncated => "truncated input",
            Error::InvalidBlockType => "invalid deflate block type",
            Error::StoredLenMismatch => "stored block length check failed",
            Error::InvalidCodeLengths => "invalid code length counts",
            Error::InvalidCodeLengthRepeat => "invalid code length repeat",
            Error::OversubscribedCode => "over-subscribed huffman code",
            Error::IncompleteCode => "incomplete huffman code",
            Error::MissingEndOfBlock => "missing end-of-block code",
            Error::InvalidCode => "invalid huffman code",
            Error::InvalidLengthSymbol => "invalid length symbol",
            Error::InvalidDistanceSymbol => "invalid distance symbol",
            Error::DistanceTooFar => "distance too far back",
            Error::BadMagic => "bad gzip magic",
            Error::UnsupportedMethod => "unsupported gzip method",
            Error::ReservedFlags => "reserved gzip flags set",
            Error::HeaderCrc => "gzip header crc mismatch",
            Error::Crc32Mismatch => "gzip crc32 mismatch",
            Error::SizeMismatch => "gzip isize mismatch",
            Error::TrailingGarbage => "trailing garbage after gzip member",
            Error::BadChecksum => "tar header checksum mismatch",
            Error::BadNumber => "bad numeric field",
            Error::BadPax => "malformed pax record",
            Error::MetaTooLarge => "tar metadata too large",
            Error::UnsupportedType(_) => "unsupported tar type",
            Error::InvalidUtf8 => "tar string is not utf-8",
            Error::SizeOverflow => "tar size overflow",
            Error::UnsafePath => "unsafe path",
        }
    }

    /// Drop the sink payload, mapping to `Error<()>` (`Sink` stays `Sink(())`).
    pub fn erase(self) -> Error<()> {
        match self {
            Error::Sink(_) => Error::Sink(()),
            Error::Failed => Error::Failed,
            Error::Truncated => Error::Truncated,
            Error::InvalidBlockType => Error::InvalidBlockType,
            Error::StoredLenMismatch => Error::StoredLenMismatch,
            Error::InvalidCodeLengths => Error::InvalidCodeLengths,
            Error::InvalidCodeLengthRepeat => Error::InvalidCodeLengthRepeat,
            Error::OversubscribedCode => Error::OversubscribedCode,
            Error::IncompleteCode => Error::IncompleteCode,
            Error::MissingEndOfBlock => Error::MissingEndOfBlock,
            Error::InvalidCode => Error::InvalidCode,
            Error::InvalidLengthSymbol => Error::InvalidLengthSymbol,
            Error::InvalidDistanceSymbol => Error::InvalidDistanceSymbol,
            Error::DistanceTooFar => Error::DistanceTooFar,
            Error::BadMagic => Error::BadMagic,
            Error::UnsupportedMethod => Error::UnsupportedMethod,
            Error::ReservedFlags => Error::ReservedFlags,
            Error::HeaderCrc => Error::HeaderCrc,
            Error::Crc32Mismatch => Error::Crc32Mismatch,
            Error::SizeMismatch => Error::SizeMismatch,
            Error::TrailingGarbage => Error::TrailingGarbage,
            Error::BadChecksum => Error::BadChecksum,
            Error::BadNumber => Error::BadNumber,
            Error::BadPax => Error::BadPax,
            Error::MetaTooLarge => Error::MetaTooLarge,
            Error::UnsupportedType(t) => Error::UnsupportedType(t),
            Error::InvalidUtf8 => Error::InvalidUtf8,
            Error::SizeOverflow => Error::SizeOverflow,
            Error::UnsafePath => Error::UnsafePath,
        }
    }
}
