// SPDX-License-Identifier: Apache-2.0

use std::sync::OnceLock;

use anyhow::Result;
use libbpf_rs::{RingBuffer, RingBufferBuilder};
use nix::sys::signal::Signal;
use zerocopy::FromBytes;

include!(concat!(env!("OUT_DIR"), "/logging_types.rs"));

impl log_hdr {
    /// Parse the type_ field from the generated C binding of struct log_hdr into
    /// a variant of the LogLevel enum derived from logging_types.h using strum.
    ///
    /// Defaults to LOG_LEVEL_OFF.
    pub fn level(&self) -> LogLevel {
        // from_repr is derived from strum_macros::FromRepr in build.rs
        LogLevel::from_repr(self.level as u32).unwrap_or(LogLevel::LOG_LEVEL_ERROR)
    }

    /// Parse the type_ field from the generated C binding of struct log_hdr into
    /// a variant of the LogReason enum derived from logging_types.h using strum.
    ///
    /// Defaults to LOG_REASON_UNKNOWN
    fn reason(&self) -> LogReason {
        // from_repr is derived from strum_macros::FromRepr in build.rs
        LogReason::from_repr(self.reason as u32).unwrap_or(LogReason::LOG_REASON_UNKNOWN)
    }

    /// Convert LogReason enum variant to a minimized string
    fn reason_str(&self) -> String {
        enum_str_no_prefix(self.reason(), "LOG_REASON_")
    }

    /// Parse the type_ field from the generated C binding of struct log_hdr into
    /// a variant of the EventType enum derived from logging_types.h using strum.
    ///
    /// Defaults to LOG_REASON_UNKNOWN
    pub fn type_(&self) -> EventType {
        // from_repr is derived from strum_macros::FromRepr in build.rs
        EventType::from_repr(self.type_ as u32).unwrap_or(EventType::EVENT_TYPE_UNKNOWN)
    }

    /// Convert EventType enum variant to a minimized string
    fn type_str(&self) -> String {
        enum_str_no_prefix(self.type_(), "EVENT_TYPE_")
    }
}

impl std::fmt::Display for log_hdr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut comm_str = char_array_to_str(&self.comm);
        if comm_str.is_empty() {
            comm_str = "(empty)";
        }
        let policy_str: String = if self.pol_id == crate::seabee::NO_POL_ID.into()
            || self.pol_id == crate::seabee::BASE_POLICY_ID.into()
        {
            String::from("SeaBee")
        } else {
            //TODO: would be cool if we could use the policy name rather than id
            format!("SeaBee policy {}", self.pol_id)
        };
        write!(
            f,
            "{}: {}: {} {}({})",
            policy_str,
            self.type_str(),
            self.reason_str(),
            comm_str,
            self.pid
        )
    }
}

/// Builds and reads from an eBPF ringbuffer.
///
/// This method loops continuously until interrupted (usually a SIGINT signal)
pub fn setup_logger<'a>(ringbuf: &libbpf_rs::MapHandle) -> Result<RingBuffer<'a>> {
    let mut rbb = RingBufferBuilder::new();
    rbb.add(ringbuf, rb_callback)?;
    Ok(rbb.build()?)
}

/// Reduce boilerplate when adding a new log struct to logging.rs
#[macro_export]
macro_rules! log_struct {
    ($t:ty,$h:ident,$d:ident) => {
        match <$t>::ref_from_bytes($d) {
            Ok(log_struct) => {
                log(
                    $h.level(),
                    // ref_from_bytes is derived from zerocopy_derive::FromBytes in build.rs
                    format!("{} {}", $h, log_struct.to_string()),
                )
            }
            Err(e) => log(
                $h.level(),
                format!("{} (unable to parse log struct - {}) {:?}", $h, e, $d),
            ),
        }
    };
}

/// Callback that can be registered with a ringbuffer map.
///
/// Every log struct defined by BPF programs will have an associated
/// EventType specified in the log_hdr that links the log to a generated
/// C binding of the log struct.
///
/// When a new BPF program is implemented, you must add a new match arm
/// in this function to get the logging system to print out your structure
///
/// An example is provided:
///
/// ```ignore
/// EventType::EVENT_TYPE_GENERIC => {
///     log_struct!(generic::generic_log, data)
/// }
/// ```
///
/// If you do not register your BPF program's structure, the raw bytes from
/// the ringbuf will be output to the string
fn rb_callback(data: &[u8]) -> i32 {
    if let Some(header) = log_header(data) {
        match header.type_() {
            EventType::EVENT_TYPE_MSG => {
                log_struct!(generic_msg_log, header, data)
            }
            EventType::EVENT_TYPE_INODE_UNLINK => {
                log_struct!(inode_access_log, header, data)
            }
            EventType::EVENT_TYPE_SB_UMOUNT => {
                log_struct!(sb_umount_log, header, data)
            }
            EventType::EVENT_TYPE_BPF_MAP => {
                log_struct!(bpf_map_log, header, data)
            }
            EventType::EVENT_TYPE_TASK_KILL => {
                log_struct!(task_kill_log, header, data)
            }
            EventType::EVENT_TYPE_KERNEL_MODULE_REQUEST => {
                log_struct!(kernel_module_request_log, header, data)
            }
            EventType::EVENT_TYPE_KERNEL_READ_FILE => {
                log_struct!(kernel_read_file_log, header, data)
            }
            EventType::EVENT_TYPE_KERNEL_LOAD_DATA => {
                log_struct!(kernel_load_data_log, header, data)
            }
            EventType::EVENT_TYPE_PTRACE_ACCESS_CHECK => {
                log_struct!(ptrace_access_check_log, header, data)
            }
            EventType::EVENT_TYPE_FILE_OPEN => {
                log_struct!(inode_access_log, header, data)
            }
            // the default case is for log_generic() and other log structures
            // that haven't yet been implemented in Rust
            _ => {
                let hdr_size = std::mem::size_of::<log_hdr>();
                if data.len() == hdr_size {
                    log(header.level(), format!("{header}"))
                } else {
                    log(
                        header.level(),
                        format!(
                            "{} (unimplemented log struct for {} bytes of data) {:?}",
                            header,
                            hdr_size - data.len(),
                            data
                        ),
                    )
                }
            }
        }
    }
    0
}

/// Outputs a [tracing::Event] according to the log level.
pub fn log(level: LogLevel, log: String) {
    match level {
        LogLevel::LOG_LEVEL_OFF => (),
        LogLevel::LOG_LEVEL_TRACE => tracing::trace!("{}", log),
        LogLevel::LOG_LEVEL_DEBUG => tracing::debug!("{}", log),
        LogLevel::LOG_LEVEL_INFO => tracing::info!("{}", log),
        LogLevel::LOG_LEVEL_WARN => tracing::warn!("{}", log),
        LogLevel::LOG_LEVEL_ERROR => tracing::error!("{}", log),
    };
}

/// Static global to use within ringbuffer callbacks
pub static LOG_LEVEL: OnceLock<LogLevel> = OnceLock::new();

pub static LOG_FILTER: OnceLock<std::collections::HashSet<EventType>> = OnceLock::new();

/// Attempts to transmute raw bytes into a [log_hdr]
///
/// The input bytes are expected to come from a eBPF ringbuffer
pub fn log_header(data: &[u8]) -> Option<&log_hdr> {
    // `ref_from_prefix` is derived from `zerocopy_derive::FromBytes` in `build.rs`
    if let Ok((header, _)) = log_hdr::ref_from_prefix(data) {
        // don't parse a log that isn't going to be printed
        if header.level() as u32 > *LOG_LEVEL.get().unwrap() as u32 {
            return None;
        }
        if LOG_FILTER.get().unwrap().contains(&header.type_()) {
            return None;
        }
        Some(header)
    } else {
        log(
            LogLevel::LOG_LEVEL_ERROR,
            format!("(unable to parse log header) {data:?}"),
        );
        None
    }
}

/// Utility function which attempts to decode an array of signed bytes
/// (char[] in C) into a UTF-8 string.
pub fn char_array_to_str(array: &[u8]) -> &str {
    match std::ffi::CStr::from_bytes_until_nul(array) {
        Ok(cstr) => cstr.to_str().unwrap_or("(non-utf8 string)"),
        Err(_) => "(bad bytes)",
    }
}

/// Utility function which takes any type that implements AsRef<str> (&str) and
/// outputs a String that has the provided prefix stripped and ASCII characters
/// converted to lowercase.
fn enum_str_no_prefix<T: AsRef<str>>(bindgen_enum: T, prefix: &str) -> String {
    bindgen_enum
        .as_ref()
        .strip_prefix(prefix)
        .unwrap_or("(error)")
        .to_ascii_lowercase()
}

impl std::fmt::Display for generic_msg_log {
    /// Formats a log from the sb_umount BPF program
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let msg = char_array_to_str(&self.msg);
        write!(f, "{msg}")
    }
}

impl std::fmt::Display for sb_umount_log {
    /// Formats a log from the sb_umount BPF program
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "dev {}", self.target_dev)
    }
}

impl std::fmt::Display for bpf_map_log {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let name = char_array_to_str(&self.name);
        write!(f, "access to map {}({})", name, self.map_id)
    }
}

impl std::fmt::Display for task_kill_log {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let signal_str = if let Ok(signal) = Signal::try_from(self.signum) {
            format!("{}({})", signal.as_str(), self.signum)
        } else {
            format!("unknown({})", self.signum)
        };
        let target_comm = char_array_to_str(&self.target_comm);

        write!(
            f,
            "send {} to {}({})",
            signal_str, target_comm, self.target_pid
        )
    }
}
impl std::fmt::Display for kernel_module_request_log {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let name = char_array_to_str(&self.kmod_name);
        write!(f, "auto load module: '{name}'")
    }
}

impl std::fmt::Display for kernel_read_file_log {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let filename = char_array_to_str(&self.filename);
        write!(f, "load file '{}', id: {}", filename, self.id)
    }
}

impl std::fmt::Display for kernel_load_data_log {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "id: {}", self.id)
    }
}

impl std::fmt::Display for ptrace_access_check_log {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let target_comm = char_array_to_str(&self.target_comm);
        write!(f, "ptrace {}({})", target_comm, self.target_pid)
    }
}

impl std::fmt::Display for inode_access_log {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let name = char_array_to_str(&self.name);
        write!(f, "access to {name}")
    }
}
