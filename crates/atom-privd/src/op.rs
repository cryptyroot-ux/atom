//! The closed set of host operations (KRN-002).
//!
//! Privilege escalation is a typed enum, not a string: there is no "run
//! arbitrary command" variant, and every variant validates its own schema.
//! An operation names, from its own shape, the `operation` and resource it
//! stands for, so the broker can hold it against a [`atom_capability`] grant
//! without a lookup table.

use std::net::Ipv4Addr;

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// A single host-administration operation the unprivileged runtime may request.
///
/// The enum is closed and internally tagged on `op`, so an unknown tag is not a
/// `HostOp` at all: it is refused at deserialization, before it can name itself
/// (deny-by-default).
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum HostOp {
    /// Write `contents` to `path`, replacing what is there.
    WriteFile {
        /// The absolute path written to.
        path: String,
        /// The bytes to write, as UTF-8.
        contents: String,
    },
    /// Remove the file at `path`.
    RemoveFile {
        /// The absolute path removed.
        path: String,
    },
    /// Spawn `program` with `args`, without a shell.
    SpawnProcess {
        /// The absolute path of the executable; never resolved through `PATH`.
        program: String,
        /// The argument vector, passed verbatim.
        args: Vec<String>,
    },
    /// Admit `allow_cidr` on `interface`.
    ConfigureNetwork {
        /// The interface reconfigured.
        interface: String,
        /// The CIDR block admitted, as `a.b.c.d/n`.
        allow_cidr: String,
    },
    /// Create a directory (and parents) within the sandbox.
    CreateDirectory {
        /// The absolute path to create.
        path: String,
    },
    /// Copy a file within the sandbox atomically.
    CopyFile {
        /// The absolute source path.
        source: String,
        /// The absolute destination path.
        destination: String,
    },
}

/// Why a [`HostOp`] failed its schema check.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum OpError {
    /// A required field carried only whitespace.
    #[error("`{field}` must not be blank")]
    BlankField {
        /// The blank field.
        field: &'static str,
    },
    /// A path or program was relative, so its meaning depends on the caller.
    #[error("`{field}` must be an absolute path, not `{value}`")]
    RelativePath {
        /// The offending field.
        field: &'static str,
        /// The value that was not absolute.
        value: String,
    },
    /// A CIDR block did not parse as `a.b.c.d/n` with `n` in `0..=32`.
    #[error("`{field}` is not a valid IPv4 CIDR: `{value}`")]
    MalformedCidr {
        /// The offending field.
        field: &'static str,
        /// The value that did not parse.
        value: String,
    },
}

impl HostOp {
    /// The wire tag of this variant, matching serde's `snake_case` rename.
    #[must_use]
    pub fn kind(&self) -> &'static str {
        match self {
            Self::WriteFile { .. } => "write_file",
            Self::RemoveFile { .. } => "remove_file",
            Self::SpawnProcess { .. } => "spawn_process",
            Self::ConfigureNetwork { .. } => "configure_network",
            Self::CreateDirectory { .. } => "create_directory",
            Self::CopyFile { .. } => "copy_file",
        }
    }

    /// The grant operation this op requires, in the grant's vocabulary.
    #[must_use]
    pub fn operation(&self) -> &'static str {
        match self {
            Self::WriteFile { .. } => "write",
            Self::RemoveFile { .. } => "delete",
            Self::SpawnProcess { .. } => "spawn",
            Self::ConfigureNetwork { .. } => "configure",
            Self::CreateDirectory { .. } => "create",
            Self::CopyFile { .. } => "copy",
        }
    }

    /// The type of the resource this op acts on, for the grant's selector.
    #[must_use]
    pub fn resource_type(&self) -> &'static str {
        match self {
            Self::WriteFile { .. } | Self::RemoveFile { .. } | Self::CreateDirectory { .. } => {
                "file"
            }
            Self::SpawnProcess { .. } => "process",
            Self::ConfigureNetwork { .. } => "network",
            Self::CopyFile { .. } => "file",
        }
    }

    /// The resource this op acts on, for the grant's selector and the permit.
    #[must_use]
    pub fn resource_id(&self) -> String {
        match self {
            Self::WriteFile { path, .. }
            | Self::RemoveFile { path }
            | Self::CreateDirectory { path } => path.clone(),
            Self::SpawnProcess { program, .. } => program.clone(),
            Self::ConfigureNetwork { interface, .. } => interface.clone(),
            Self::CopyFile {
                source,
                destination,
            } => format!("{source} -> {destination}"),
        }
    }

    /// Validates the operation's input schema.
    ///
    /// # Errors
    ///
    /// [`OpError`] naming the first field that is blank, a relative path where
    /// an absolute one is required, or a malformed CIDR.
    pub fn validate(&self) -> Result<(), OpError> {
        match self {
            Self::WriteFile { path, .. } => absolute(path, "path"),
            Self::RemoveFile { path } => absolute(path, "path"),
            Self::SpawnProcess { program, args } => {
                absolute(program, "program")?;
                for (index, arg) in args.iter().enumerate() {
                    if arg.is_empty() {
                        return Err(OpError::BlankField {
                            field: arg_field(index),
                        });
                    }
                }
                Ok(())
            }
            Self::ConfigureNetwork {
                interface,
                allow_cidr,
            } => {
                non_blank(interface, "interface")?;
                cidr(allow_cidr, "allow_cidr")
            }
            Self::CreateDirectory { path } => absolute(path, "path"),
            Self::CopyFile {
                source,
                destination,
            } => {
                absolute(source, "source")?;
                absolute(destination, "destination")
            }
        }
    }
}

/// Fails unless `value` carries something other than whitespace.
fn non_blank(value: &str, field: &'static str) -> Result<(), OpError> {
    if value.trim().is_empty() {
        return Err(OpError::BlankField { field });
    }
    Ok(())
}

/// Fails unless `value` is a non-blank, absolute path.
fn absolute(value: &str, field: &'static str) -> Result<(), OpError> {
    non_blank(value, field)?;
    if !value.starts_with('/') {
        return Err(OpError::RelativePath {
            field,
            value: value.to_owned(),
        });
    }
    Ok(())
}

/// Fails unless `value` parses as an IPv4 CIDR `a.b.c.d/n`, `n` in `0..=32`.
fn cidr(value: &str, field: &'static str) -> Result<(), OpError> {
    let malformed = || OpError::MalformedCidr {
        field,
        value: value.to_owned(),
    };
    let (addr, prefix) = value.split_once('/').ok_or_else(malformed)?;
    addr.parse::<Ipv4Addr>().map_err(|_| malformed())?;
    match prefix.parse::<u8>() {
        Ok(bits) if bits <= 32 => Ok(()),
        _ => Err(malformed()),
    }
}

/// The stable name of the `args[index]` field, for [`OpError`].
fn arg_field(index: usize) -> &'static str {
    // A small, bounded set covers every realistic argument vector; anything
    // longer is named generically rather than leaking an unbounded string.
    const NAMES: [&str; 8] = [
        "args[0]", "args[1]", "args[2]", "args[3]", "args[4]", "args[5]", "args[6]", "args[7]",
    ];
    NAMES.get(index).copied().unwrap_or("args[..]")
}
