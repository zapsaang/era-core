use indicatif::{MultiProgress, ProgressBar};
use std::io::{self, IsTerminal, Write};
use std::sync::{Arc, Mutex, OnceLock};
use tracing_subscriber::fmt::MakeWriter;

#[derive(Clone)]
pub struct CliProgressCoordinator {
    inner: Arc<CoordinatorInner>,
}

struct CoordinatorInner {
    multi_progress: MultiProgress,
    interactive: bool,
    sink: Mutex<Box<dyn Write + Send>>,
}

static COORDINATOR: OnceLock<CliProgressCoordinator> = OnceLock::new();

fn global_coordinator() -> &'static CliProgressCoordinator {
    COORDINATOR.get_or_init(|| {
        CliProgressCoordinator::with_sink(io::stderr().is_terminal(), Box::new(io::stderr()))
    })
}

pub fn init() {
    let _ = global_coordinator();
}

pub fn progress_bar(len: u64) -> ProgressBar {
    global_coordinator().add_progress_bar(len)
}

pub fn spinner() -> ProgressBar {
    global_coordinator().add_spinner()
}

pub struct ProgressMakeWriter;

impl<'a> MakeWriter<'a> for ProgressMakeWriter {
    type Writer = ProgressLogWriter;

    fn make_writer(&'a self) -> Self::Writer {
        global_coordinator().make_writer().make_writer()
    }
}

impl CliProgressCoordinator {
    pub fn with_sink(interactive: bool, sink: Box<dyn Write + Send>) -> Self {
        Self {
            inner: Arc::new(CoordinatorInner {
                multi_progress: MultiProgress::new(),
                interactive,
                sink: Mutex::new(sink),
            }),
        }
    }

    pub fn add_progress_bar(&self, len: u64) -> ProgressBar {
        if self.inner.interactive {
            self.inner.multi_progress.add(ProgressBar::new(len))
        } else {
            ProgressBar::hidden()
        }
    }

    pub fn add_spinner(&self) -> ProgressBar {
        if self.inner.interactive {
            self.inner.multi_progress.add(ProgressBar::new_spinner())
        } else {
            ProgressBar::hidden()
        }
    }

    pub fn print_line(&self, line: &str) -> io::Result<()> {
        if self.inner.interactive {
            self.inner.multi_progress.suspend(|| self.write_line(line))
        } else {
            self.write_line(line)
        }
    }

    pub fn make_writer(&self) -> ProgressLogWriterFactory {
        ProgressLogWriterFactory {
            coordinator: self.clone(),
        }
    }

    fn write_line(&self, line: &str) -> io::Result<()> {
        let mut sink = self
            .inner
            .sink
            .lock()
            .map_err(|_| io::Error::other("progress sink lock poisoned"))?;
        sink.write_all(line.as_bytes())?;
        if !line.ends_with('\n') {
            sink.write_all(b"\n")?;
        }
        sink.flush()
    }
}

#[derive(Clone)]
pub struct ProgressLogWriterFactory {
    coordinator: CliProgressCoordinator,
}

impl<'a> MakeWriter<'a> for ProgressLogWriterFactory {
    type Writer = ProgressLogWriter;

    fn make_writer(&'a self) -> Self::Writer {
        ProgressLogWriter {
            coordinator: self.coordinator.clone(),
            buffer: Vec::new(),
        }
    }
}

pub struct ProgressLogWriter {
    coordinator: CliProgressCoordinator,
    buffer: Vec<u8>,
}

impl Write for ProgressLogWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.buffer.extend_from_slice(buf);

        while let Some(idx) = self.buffer.iter().position(|byte| *byte == b'\n') {
            let line = self.buffer.drain(..=idx).collect::<Vec<u8>>();
            let text = String::from_utf8_lossy(&line);
            self.coordinator
                .print_line(text.trim_end_matches(['\n', '\r']))?;
        }

        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        if self.buffer.is_empty() {
            return Ok(());
        }

        let bytes = std::mem::take(&mut self.buffer);
        let text = String::from_utf8_lossy(&bytes);

        let mut start = 0usize;
        for (idx, ch) in text.char_indices() {
            if ch == '\n' {
                self.coordinator.print_line(&text[start..idx])?;
                start = idx + ch.len_utf8();
            }
        }

        if start < text.len() {
            self.coordinator.print_line(&text[start..])?;
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Clone)]
    struct SharedBuffer {
        bytes: Arc<Mutex<Vec<u8>>>,
    }

    impl SharedBuffer {
        fn new() -> (Self, Arc<Mutex<Vec<u8>>>) {
            let bytes = Arc::new(Mutex::new(Vec::new()));
            (
                Self {
                    bytes: Arc::clone(&bytes),
                },
                bytes,
            )
        }
    }

    impl Write for SharedBuffer {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.bytes
                .lock()
                .expect("shared buffer lock poisoned")
                .extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn test_print_line_routes_through_coordinator_output() {
        let (sink, bytes) = SharedBuffer::new();
        let coordinator = CliProgressCoordinator::with_sink(false, Box::new(sink));

        coordinator
            .print_line("log line through coordinator")
            .expect("print_line should succeed");

        let output = String::from_utf8(bytes.lock().expect("shared buffer lock poisoned").clone())
            .expect("buffer should contain UTF-8 text");
        assert!(output.contains("log line through coordinator"));
    }

    #[test]
    fn test_make_writer_non_interactive_flushes_lines_without_panic() {
        let (sink, bytes) = SharedBuffer::new();
        let coordinator = CliProgressCoordinator::with_sink(false, Box::new(sink));

        let factory = coordinator.make_writer();
        let mut writer = factory.make_writer();
        writer
            .write_all(b"hello from tracing\n")
            .expect("write_all should succeed");
        writer.flush().expect("flush should succeed");

        let output = String::from_utf8(bytes.lock().expect("shared buffer lock poisoned").clone())
            .expect("buffer should contain UTF-8 text");
        assert!(output.contains("hello from tracing"));
    }

    #[test]
    fn test_make_writer_buffers_partial_line_until_flush_and_trims_crlf() {
        let (sink, bytes) = SharedBuffer::new();
        let coordinator = CliProgressCoordinator::with_sink(false, Box::new(sink));

        let factory = coordinator.make_writer();
        let mut writer = factory.make_writer();

        writer
            .write_all(b"first line\r\nsecond line")
            .expect("write_all should succeed");

        let before_flush =
            String::from_utf8(bytes.lock().expect("shared buffer lock poisoned").clone())
                .expect("buffer should contain UTF-8 text");
        assert_eq!(before_flush, "first line\n");

        writer.flush().expect("flush should succeed");

        let after_flush =
            String::from_utf8(bytes.lock().expect("shared buffer lock poisoned").clone())
                .expect("buffer should contain UTF-8 text");
        assert_eq!(after_flush, "first line\nsecond line\n");
    }
}
