use std::process::{Child, Command};
use std::sync::Arc;
use std::thread;
use std::time::SystemTime;
use std::{io::Write, sync::Mutex};

use clap::Parser;
use libturnstile::{Operation, TurnstileTracer, TurnstileTracerError};
use log::info;

/// Trace file operations of a program using libturnstile
#[derive(Parser)]
#[command(name = "fstrace")]
#[command(trailing_var_arg = true)]
struct Cli {
	/// Write output to a file instead of stderr
	#[arg(short = 'o', value_name = "FILE")]
	output: Option<String>,

	/// Add timestamps to each output line
	#[arg(short = 't', long = "timestamps")]
	timestamps: bool,

	/// Program to trace and its arguments
	#[arg(required = true, allow_hyphen_values = true)]
	command: Vec<String>,
}

fn write_operation(
	output: &mut dyn Write,
	op: &Operation,
	timestamps: bool,
) -> std::io::Result<()> {
	if timestamps {
		let now = SystemTime::now()
			.duration_since(SystemTime::UNIX_EPOCH)
			.unwrap_or_default();
		write!(output, "[{}.{:03}] ", now.as_secs(), now.subsec_millis())?;
	}
	writeln!(output, "{:?}", op)
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
	env_logger::init();

	let cli = Cli::parse();

	let mut output: Box<dyn Write> = match &cli.output {
		Some(path) => Box::new(
			std::fs::File::create(path)
				.map_err(|e| format!("failed to open output file '{}': {}", path, e))?,
		),
		None => Box::new(std::io::stderr()),
	};

	let mut tracer_box = Arc::new(Mutex::new(TurnstileTracer::new()?));

	let program = &cli.command[0];
	let args = &cli.command[1..];
	let mut cmd = Command::new(program);
	cmd.args(args);

	let mut child_box: Arc<Mutex<Option<Child>>> = Arc::new(Mutex::new(None));
	let mut error_box: Arc<Mutex<Option<TurnstileTracerError>>> = Arc::new(Mutex::new(None));

	// We need to have started monitoring and responding to events before
	// the execve even happens, so we need to do this in a separate
	// thread.
	let child_box_for_thread = Arc::clone(&child_box);
	let error_box_for_thread = Arc::clone(&error_box);
	let tracer_box_for_thread = Arc::clone(&tracer_box);
	let child_spawn_jh = thread::spawn(move || {
		let mut tracer = tracer_box_for_thread.lock().unwrap();
		match tracer.run_command(&mut cmd) {
			Ok(child) => {
				info!("Started child process with pid {}", child.id());
				child_box_for_thread.lock().unwrap().replace(child);
			}
			Err(e) => {
				error_box_for_thread.lock().unwrap().replace(e);
				return;
			}
		};
	});

	loop {
		let tracer = tracer_box.lock().unwrap();
		match tracer.yield_request() {
			Ok(Some((access_request, mut ctx))) => {
				for op in &access_request {
					write_operation(&mut output, op, cli.timestamps)?;
				}
				ctx.send_continue()?;
			}
			Ok(None) => {
				// Syscall was auto-continued by the tracer (e.g. not a
				// file operation we care about), nothing to report.
			}
			Err(e) => {
				eprintln!("fstrace: error: {}", e);
			}
		}
		if let Some(child) = child_box.lock().unwrap().as_mut() {
			if let Some(wait_res) = child.try_wait()? {
				eprintln!("fstrace: child process exited with status {}", wait_res);
				std::process::exit(wait_res.code().unwrap_or(1));
			}
		}
		if let Some(err) = error_box.lock().unwrap().take() {
			eprintln!("fstrace: error spawning child: {}", err);
			std::process::exit(1);
		}
	}
}
