// SPDX-License-Identifier: Apache-2.0
use std::time::Duration;

/// The max number of policies seabee can store. Should be large enough for any use case.
pub const SEABEE_MAX_POLICIES: u32 = 1024;

/// The max number of scopes for seabee policies.
pub const SEABEE_MAX_POLICY_SCOPES: u32 = 4096;

/// The max number of maps SeaBee can track concurrently. SeaBee tracks all maps on the system
pub const SEABEE_MAX_MAPS: u32 = 65536;

/// The /sys filesystem
pub const SYS_PATH: &str = "/sys";

/// The path to the bpf filesystem
pub const BPF_PATH: &str = "/sys/fs/bpf";

/// The default directory name for pins in the BPF filesystem
pub const PIN_DIR: &str = "/sys/fs/bpf/seabee";

/// The default directory for seabee files
pub const SEABEE_DIR: &str = "/etc/seabee";

/// The path to the seabeectl executable
pub const SEABEECTL_EXE: &str = "/usr/sbin/seabeectl";

/// The directory to store policy files
pub const POLICY_DIR: &str = "/etc/seabee/policy";

/// The directory to store policy signatures
pub const POL_SIGNATURE_DIR: &str = "/etc/seabee/policy_sigs";

/// The directory to store verification keys
pub const KEY_DIR: &str = "/etc/seabee/keys";

/// The directory to store key signatures
pub const KEY_SIGNATURE_DIR: &str = "/etc/seabee/key_sigs";

/// The path where a list of keys is stored
pub const KEYLIST_PATH: &str = "/etc/seabee/keylist.yaml";

/// The location of the SeaBee root key, which is the first key to be loaded
/// and is not verified with a signature.
pub const SEABEE_ROOT_KEY_PATH: &str = "/etc/seabee/seabee_root_key.pem";

/// The default path to the configuration file
pub const CONFIG_PATH: &str = "/etc/seabee/config.yaml";

// The path to the daemon service file, this must match the Makefile
pub const SERVICE_PATH: &str = "/etc/systemd/system/seabee.service";

// The path to the unix domain socket that seabeectl uses
pub const SOCKET_PATH: &str = "/run/seabee_sock";

/// Per-system-call timeout for socket communication between seabee and seabeectl.
pub const SOCKET_SERVER_IO_TIMEOUT: Duration = Duration::from_secs(1);
pub const SOCKET_TIMEOUT: Option<Duration> = Some(SOCKET_SERVER_IO_TIMEOUT);

/// Maximum time for seabeectl to complete an I/O operation, including retries
/// after a transient timeout or interruption.
pub const SOCKET_CLIENT_IO_TIMEOUT: Duration = Duration::from_secs(5);
