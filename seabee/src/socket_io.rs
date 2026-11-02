// SPDX-License-Identifier: Apache-2.0

use std::{
    cmp,
    io::{self, ErrorKind, Read, Write},
    thread,
    time::{Duration, Instant},
};

const RETRY_DELAY: Duration = Duration::from_millis(1);

fn timeout_error(operation: &str) -> io::Error {
    io::Error::new(ErrorKind::TimedOut, format!("timed out while {operation}"))
}

fn check_deadline(deadline: Instant, operation: &str) -> io::Result<()> {
    if Instant::now() >= deadline {
        Err(timeout_error(operation))
    } else {
        Ok(())
    }
}

fn retry_transient(error: io::Error, deadline: Instant, operation: &str) -> io::Result<()> {
    match error.kind() {
        ErrorKind::Interrupted | ErrorKind::WouldBlock | ErrorKind::TimedOut => {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Err(timeout_error(operation));
            }
            thread::sleep(cmp::min(RETRY_DELAY, remaining));
            Ok(())
        }
        _ => Err(error),
    }
}

/// Write all bytes exactly once, resuming after partial writes and transient
/// errors until the operation timeout expires.
pub(crate) fn write_all<W: Write>(
    writer: &mut W,
    mut bytes: &[u8],
    timeout: Duration,
) -> io::Result<()> {
    let deadline = Instant::now() + timeout;

    while !bytes.is_empty() {
        check_deadline(deadline, "writing to socket")?;
        match writer.write(bytes) {
            Ok(0) => return Err(ErrorKind::WriteZero.into()),
            Ok(written) => bytes = &bytes[written..],
            Err(error) => retry_transient(error, deadline, "writing to socket")?,
        }
    }

    Ok(())
}

/// Write a server response within the daemon's short I/O budget. Partial
/// writes and interruptions preserve progress, but a non-reading client must
/// not stall the synchronous daemon loop through transient-error retries.
pub(crate) fn write_response<W: Write>(
    writer: &mut W,
    mut bytes: &[u8],
    timeout: Duration,
) -> io::Result<()> {
    let deadline = Instant::now() + timeout;

    while !bytes.is_empty() {
        check_deadline(deadline, "writing response to socket")?;
        match writer.write(bytes) {
            Ok(0) => return Err(ErrorKind::WriteZero.into()),
            Ok(written) => bytes = &bytes[written..],
            Err(error) if error.kind() == ErrorKind::Interrupted => {
                retry_transient(error, deadline, "writing response to socket")?;
            }
            Err(error) => return Err(error),
        }
    }

    Ok(())
}

/// Read one newline-terminated command. EOF before the newline is an
/// incomplete request, even if the bytes received so far contain valid JSON.
pub(crate) fn read_command<R: Read>(reader: &mut R, timeout: Duration) -> io::Result<Vec<u8>> {
    let deadline = Instant::now() + timeout;
    let mut command = Vec::new();
    let mut buffer = [0_u8; 4096];

    loop {
        check_deadline(deadline, "reading command from socket")?;
        match reader.read(&mut buffer) {
            Ok(0) => {
                return Err(io::Error::new(
                    ErrorKind::UnexpectedEof,
                    "socket closed before command newline",
                ))
            }
            Ok(read) => {
                if let Some(newline) = buffer[..read].iter().position(|byte| *byte == b'\n') {
                    command.extend_from_slice(&buffer[..=newline]);
                    return Ok(command);
                }
                command.extend_from_slice(&buffer[..read]);
            }
            Err(error) => {
                retry_transient(error, deadline, "reading command from socket")?;
            }
        }
    }
}

/// Read an EOF-framed response. An immediate EOF is a premature disconnect;
/// otherwise EOF remains the response terminator used by the existing protocol.
pub(crate) fn read_response<R: Read>(reader: &mut R, timeout: Duration) -> io::Result<Vec<u8>> {
    let deadline = Instant::now() + timeout;
    let mut response = Vec::new();
    let mut buffer = [0_u8; 4096];

    loop {
        check_deadline(deadline, "reading response from socket")?;
        match reader.read(&mut buffer) {
            Ok(0) if response.is_empty() => {
                return Err(io::Error::new(
                    ErrorKind::UnexpectedEof,
                    "socket closed before response",
                ))
            }
            Ok(0) => return Ok(response),
            Ok(read) => response.extend_from_slice(&buffer[..read]),
            Err(error) => {
                retry_transient(error, deadline, "reading response from socket")?;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{
        collections::VecDeque,
        io::{self, Cursor, ErrorKind, Read, Write},
        os::unix::net::UnixStream,
        thread,
        time::{Duration, Instant},
    };

    use super::{read_command, read_response, write_all, write_response};

    enum WriteAction {
        Error(ErrorKind),
        Limit(usize),
    }

    struct FaultWriter {
        actions: VecDeque<WriteAction>,
        output: Vec<u8>,
    }

    impl Write for FaultWriter {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            match self.actions.pop_front() {
                Some(WriteAction::Error(kind)) => Err(kind.into()),
                Some(WriteAction::Limit(limit)) => {
                    let written = limit.min(bytes.len());
                    self.output.extend_from_slice(&bytes[..written]);
                    Ok(written)
                }
                None => {
                    self.output.extend_from_slice(bytes);
                    Ok(bytes.len())
                }
            }
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    enum ReadAction {
        Data(&'static [u8]),
        Error(ErrorKind),
        Eof,
    }

    struct FaultReader {
        actions: VecDeque<ReadAction>,
    }

    impl Read for FaultReader {
        fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
            match self.actions.pop_front().unwrap_or(ReadAction::Eof) {
                ReadAction::Data(data) => {
                    assert!(data.len() <= buffer.len());
                    buffer[..data.len()].copy_from_slice(data);
                    Ok(data.len())
                }
                ReadAction::Error(kind) => Err(kind.into()),
                ReadAction::Eof => Ok(0),
            }
        }
    }

    struct BlockingReader {
        prefix: Option<&'static [u8]>,
        attempts: usize,
    }

    impl Read for BlockingReader {
        fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
            self.attempts += 1;
            if let Some(prefix) = self.prefix.take() {
                buffer[..prefix.len()].copy_from_slice(prefix);
                Ok(prefix.len())
            } else {
                Err(ErrorKind::WouldBlock.into())
            }
        }
    }

    struct TrickleReader {
        remaining: usize,
        delay: Duration,
    }

    impl Read for TrickleReader {
        fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
            if self.remaining == 0 {
                return Ok(0);
            }
            thread::sleep(self.delay);
            buffer[0] = b'x';
            self.remaining -= 1;
            Ok(1)
        }
    }

    struct TrickleWriter {
        delay: Duration,
        output: Vec<u8>,
    }

    impl Write for TrickleWriter {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            thread::sleep(self.delay);
            self.output.push(bytes[0]);
            Ok(1)
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn retries_partial_writes_without_replaying_bytes() {
        let request = br#"{"Update":{"target_path":"policy.yaml","sig_path":null,"digest":null}}
"#;
        let mut writer = FaultWriter {
            actions: VecDeque::from([
                WriteAction::Limit(7),
                WriteAction::Error(ErrorKind::Interrupted),
                WriteAction::Limit(3),
                WriteAction::Error(ErrorKind::WouldBlock),
                WriteAction::Error(ErrorKind::TimedOut),
            ]),
            output: Vec::new(),
        };

        write_all(&mut writer, request, Duration::from_secs(1)).unwrap();

        assert_eq!(writer.output, request);
        assert_eq!(
            writer.output.iter().filter(|byte| **byte == b'\n').count(),
            1
        );
    }

    #[test]
    fn retries_partial_and_interrupted_reads() {
        let mut reader = FaultReader {
            actions: VecDeque::from([
                ReadAction::Data(b"res"),
                ReadAction::Error(ErrorKind::Interrupted),
                ReadAction::Error(ErrorKind::WouldBlock),
                ReadAction::Data(b"pon"),
                ReadAction::Error(ErrorKind::TimedOut),
                ReadAction::Data(b"se"),
                ReadAction::Eof,
            ]),
        };

        let response = read_response(&mut reader, Duration::from_secs(1)).unwrap();

        assert_eq!(response, b"response");
    }

    #[test]
    fn delayed_response_survives_multiple_socket_timeouts() {
        let (mut client, mut server) = UnixStream::pair().unwrap();
        client
            .set_read_timeout(Some(Duration::from_millis(10)))
            .unwrap();

        let server_thread = thread::spawn(move || {
            let command = read_command(&mut server, Duration::from_secs(1)).unwrap();
            assert_eq!(command, b"\"List\"\n");
            thread::sleep(Duration::from_millis(40));
            write_response(&mut server, b"response", Duration::from_secs(1)).unwrap();
            server.shutdown(std::net::Shutdown::Write).unwrap();
        });

        write_all(&mut client, b"\"List\"\n", Duration::from_secs(1)).unwrap();
        let response = read_response(&mut client, Duration::from_secs(1)).unwrap();

        assert_eq!(response, b"response");
        server_thread.join().unwrap();
    }

    #[test]
    fn incomplete_command_is_rejected() {
        let mut command_without_newline = Cursor::new(b"\"List\"".as_slice());

        let error =
            read_command(&mut command_without_newline, Duration::from_millis(100)).unwrap_err();

        assert_eq!(error.kind(), ErrorKind::UnexpectedEof);
    }

    #[test]
    fn premature_disconnect_is_rejected() {
        let (mut client, server) = UnixStream::pair().unwrap();
        drop(server);

        let error = read_response(&mut client, Duration::from_millis(100)).unwrap_err();

        assert_eq!(error.kind(), ErrorKind::UnexpectedEof);
    }

    #[test]
    fn incomplete_response_times_out_instead_of_succeeding() {
        let mut reader = BlockingReader {
            prefix: Some(b"partial"),
            attempts: 0,
        };

        let error = read_response(&mut reader, Duration::from_millis(25)).unwrap_err();

        assert_eq!(error.kind(), ErrorKind::TimedOut);
        assert!(reader.attempts < 100);
    }

    #[test]
    fn permanent_would_block_terminates_within_bound() {
        let mut reader = BlockingReader {
            prefix: None,
            attempts: 0,
        };
        let started = Instant::now();

        let error = read_response(&mut reader, Duration::from_millis(25)).unwrap_err();

        assert_eq!(error.kind(), ErrorKind::TimedOut);
        assert!(started.elapsed() < Duration::from_secs(5));
        assert!(reader.attempts < 100);
    }

    #[test]
    fn permanent_write_failure_is_preserved() {
        let mut writer = FaultWriter {
            actions: VecDeque::from([WriteAction::Error(ErrorKind::BrokenPipe)]),
            output: Vec::new(),
        };

        let error = write_all(&mut writer, b"request\n", Duration::from_secs(1)).unwrap_err();

        assert_eq!(error.kind(), ErrorKind::BrokenPipe);
        assert!(writer.output.is_empty());
    }

    #[test]
    fn server_response_does_not_retry_would_block() {
        let mut writer = FaultWriter {
            actions: VecDeque::from([
                WriteAction::Limit(3),
                WriteAction::Error(ErrorKind::WouldBlock),
            ]),
            output: Vec::new(),
        };

        let error = write_response(&mut writer, b"response", Duration::from_secs(1)).unwrap_err();

        assert_eq!(error.kind(), ErrorKind::WouldBlock);
        assert_eq!(writer.output, b"res");
    }

    #[test]
    fn server_command_wait_is_bounded() {
        let mut reader = BlockingReader {
            prefix: None,
            attempts: 0,
        };

        let error = read_command(&mut reader, Duration::from_millis(25)).unwrap_err();

        assert_eq!(error.kind(), ErrorKind::TimedOut);
        assert!(reader.attempts < 100);
    }

    #[test]
    fn slow_command_client_cannot_extend_server_budget() {
        let mut reader = TrickleReader {
            remaining: 20,
            delay: Duration::from_millis(5),
        };

        let error = read_command(&mut reader, Duration::from_millis(25)).unwrap_err();

        assert_eq!(error.kind(), ErrorKind::TimedOut);
        assert!(reader.remaining > 0);
    }

    #[test]
    fn slow_response_client_cannot_extend_server_budget() {
        let mut writer = TrickleWriter {
            delay: Duration::from_millis(5),
            output: Vec::new(),
        };
        let response = b"twenty-byte-response";

        let error = write_response(&mut writer, response, Duration::from_millis(25)).unwrap_err();

        assert_eq!(error.kind(), ErrorKind::TimedOut);
        assert!(writer.output.len() < response.len());
        assert_eq!(writer.output, response[..writer.output.len()]);
    }

    #[test]
    fn serial_server_handles_multiple_waiting_clients_once_each() {
        const CLIENTS: usize = 6;
        let mut server_streams = Vec::new();
        let mut clients = Vec::new();

        for client_id in 0..CLIENTS {
            let (client, server) = UnixStream::pair().unwrap();
            client
                .set_read_timeout(Some(Duration::from_millis(5)))
                .unwrap();
            server_streams.push(server);
            clients.push(thread::spawn(move || {
                let request = format!("{client_id}\n");
                let mut client = client;
                write_all(&mut client, request.as_bytes(), Duration::from_secs(1)).unwrap();
                read_response(&mut client, Duration::from_secs(1)).unwrap()
            }));
        }

        let server = thread::spawn(move || {
            let mut executed = Vec::new();
            for mut stream in server_streams {
                let request = read_command(&mut stream, Duration::from_secs(1)).unwrap();
                executed.push(request);
                thread::sleep(Duration::from_millis(10));
                write_response(&mut stream, b"ok", Duration::from_secs(1)).unwrap();
                stream.shutdown(std::net::Shutdown::Write).unwrap();
            }
            executed
        });

        for client in clients {
            assert_eq!(client.join().unwrap(), b"ok");
        }
        let executed = server.join().unwrap();
        assert_eq!(executed.len(), CLIENTS);
        for (client_id, request) in executed.iter().enumerate() {
            assert_eq!(request, format!("{client_id}\n").as_bytes());
        }
    }
}
