// SPDX-License-Identifier: MIT
// Copyright (c) 2025 Jesof

//! Typed `RouterOS` snapshot and protocol errors.

use thiserror::Error;

/// Invalid or inconsistent router snapshot error.
///
/// These are produced when parsed router output is malformed, incomplete, or
/// internally inconsistent. They are query-level failures: a protocol-clean
/// connection remains reusable and pool backoff is not triggered.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum SnapshotError {
    /// A required response attribute is missing.
    #[error("missing field {field}")]
    MissingField {
        /// Required attribute name.
        field: String,
    },

    /// A required numeric response attribute is not a valid number.
    #[error("invalid numeric field {field} in {context}")]
    InvalidNumericField {
        /// Attribute name.
        field: String,
        /// Collection context for diagnostics.
        context: String,
    },

    /// The same object id appears more than once in a snapshot.
    #[error("duplicate {kind} id")]
    DuplicateId {
        /// Object kind (interface, firewall rule).
        kind: &'static str,
    },

    /// Interface `running` attribute is neither `true` nor `false`.
    #[error("invalid interface running state")]
    InvalidInterfaceRunningState,

    /// A conntrack source address does not parse as an IP.
    #[error("invalid conntrack source address")]
    InvalidConntrackSourceAddress,

    /// `/system/resource/print` returned more than one row.
    #[error("expected one system resource row")]
    ExpectedSingleSystemRow,

    /// System resource bounds or uptime are out of range.
    #[error("invalid system resource bounds or uptime")]
    InvalidSystemResource,

    /// Certificate expiry date is unusable.
    #[error("invalid certificate expiry")]
    InvalidCertificateExpiry,

    /// `WireGuard` byte counts exceed the signed gauge range.
    #[error("wireguard byte count exceeds gauge range")]
    WireguardByteCountOutOfRange,

    /// `WireGuard` handshake duration cannot be parsed.
    #[error("invalid wireguard handshake duration")]
    InvalidWireguardHandshake,

    /// `count-only` reply lacks a valid terminal count.
    #[error("invalid count-only completion")]
    InvalidCountOnlyCompletion,

    /// An empty interface snapshot was received for system/interfaces.
    #[error("empty interface snapshot")]
    EmptyInterfaceSnapshot,

    /// `WireGuard` peer counts across queries are inconsistent.
    #[error("inconsistent snapshot: wireguard peers count mismatch")]
    WireguardPeersCountMismatch,

    /// Firewall count mismatch across sections.
    #[error("inconsistent snapshot: firewall count mismatch in sections {sections}")]
    FirewallCountMismatch {
        /// Section names with mismatched counts.
        sections: String,
    },

    /// An unexpectedly empty firewall snapshot was not verified.
    #[error("unverified empty firewall snapshot")]
    UnverifiedEmptyFirewallSnapshot,

    /// Fallback for free-form snapshot failure messages.
    #[error("{0}")]
    GenericMessage(String),
}

/// `RouterOS` wire-protocol framing or sentence violation.
///
/// These are connection-level failures: the response stream is desynchronized
/// and the connection must be discarded rather than returned to the pool.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum ProtocolError {
    /// Encoded word length exceeds 32 bits.
    #[error("word length exceeds 32 bits")]
    WordLengthTooLarge,

    /// Word length prefix uses a reserved encoding.
    #[error("reserved word length prefix")]
    ReservedWordLengthPrefix,

    /// Word length exceeds the platform `usize` limit.
    #[error("word length exceeds platform limit")]
    WordLengthPlatformLimit,

    /// A command was issued while a previous command was unfinished.
    #[error("connection has an unfinished command")]
    UnfinishedCommand,

    /// A request word is empty or exceeds the maximum length.
    #[error("invalid request word length")]
    InvalidRequestWordLength,

    /// Response sentence has an unknown type tag.
    #[error("unknown response sentence type")]
    UnknownSentenceType,

    /// Response exceeded the per-command sentence budget.
    #[error("response sentence limit exceeded")]
    SentenceLimitExceeded,

    /// A response sentence has an empty type tag.
    #[error("empty response sentence")]
    EmptySentence,

    /// A response attribute is not `=key=value` or `.key=value`.
    #[error("malformed response attribute")]
    MalformedAttribute,

    /// A response attribute has an empty or duplicate key.
    #[error("empty or duplicate response attribute")]
    EmptyOrDuplicateAttribute,

    /// A response sentence exceeded the per-sentence word budget.
    #[error("sentence word limit exceeded")]
    SentenceWordLimitExceeded,

    /// A response exceeded the per-command word budget.
    #[error("response word limit exceeded")]
    WordLimitExceeded,

    /// A single response word exceeds the maximum length.
    #[error("word length limit exceeded")]
    WordLengthLimitExceeded,

    /// A response exceeded the per-command byte budget.
    #[error("response byte limit exceeded")]
    ByteLimitExceeded,

    /// A response word is not valid UTF-8.
    #[error("word is not valid UTF-8")]
    InvalidUtf8,
}
