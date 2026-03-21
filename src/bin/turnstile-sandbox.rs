use std::{
	env,
	ffi::{CStr, CString},
	process::Command,
	sync::{Arc, OnceLock},
	thread::{self, sleep},
	time::Duration,
};

use clap::Parser;
use libturnstile::{BindMountSandbox, MountAttributes};
use log::error;

use crate::common::{ProcPidFd, handle_child_result};

mod common;

/// Trace file operations of a program using libturnstile
#[derive(Parser)]
#[command(name = "turnstile-sandbox")]
#[command(trailing_var_arg = true)]
struct Cli {
	/// Block the sandboxed process from creating more unprivileged user
	/// namespaces.
	#[arg(long = "block-nested-userns")]
	block_more_userns: bool,

	/// Program to run and its arguments
	#[arg(required = true)]
	command: Vec<String>,
}

#[derive(Debug)]
struct Context {
	sandbox: BindMountSandbox,
	pidfd: OnceLock<ProcPidFd>,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
	common::init_logger();

	let cli = Cli::parse();

	let context = Arc::new(Context {
		sandbox: BindMountSandbox::new(cli.block_more_userns)?,
		pidfd: OnceLock::new(),
	});

	let sandbox = &context.sandbox;
	sandbox.mount_host_into_ns(c"/usr", c"/usr", &MountAttributes::rx())?;
	sandbox.mount_host_into_ns(c"/bin", c"/bin", &MountAttributes::rx())?;
	sandbox.mount_host_into_ns(c"/lib", c"/lib", &MountAttributes::rx())?;
	if std::fs::exists("/lib64").unwrap_or(false) {
		sandbox.mount_host_into_ns(c"/lib64", c"/lib64", &MountAttributes::rx())?;
	}
	sandbox.mount_host_into_ns(c"/etc", c"/etc", &MountAttributes::rx())?;
	sandbox.mount_host_into_ns(c"/dev", c"/dev", &MountAttributes::rwx())?;
	sandbox.mount_host_into_ns(c"/proc", c"/proc", &MountAttributes::rwx())?;
	let pwd = std::env::current_dir()?
		.into_os_string()
		.into_encoded_bytes();
	let pwd = CString::new(pwd).unwrap();
	sandbox.mount_host_into_ns(&pwd, &pwd, &MountAttributes::ro())?;
	let sandbox_tmp = env::temp_dir().join("sandbox-tmp");
	std::fs::create_dir_all(&sandbox_tmp)?;
	sandbox.mount_host_into_ns(
		&CString::new(sandbox_tmp.into_os_string().into_encoded_bytes()).unwrap(),
		c"/tmp",
		&MountAttributes::rwx(),
	)?;

	let program = &cli.command[0];
	let args = &cli.command[1..];
	let mut cmd = Command::new(program);
	cmd.args(args);

	let context_for_thread = context.clone();
	thread::spawn(move || {
		let context = context_for_thread;

		eprintln!("In 10 seconds, will allow write access on {:?}", pwd);
		sleep(Duration::from_secs(10));

		eprintln!("Now allowing write access on {:?}", pwd);
		if let Err(e) = context.sandbox.set_mount_attr_within_ns(
			&pwd,
			&MountAttributes::rw(),
			&MountAttributes::ro(),
		) {
			error!("Failed to set mount attributes: {e}");
		}

		eprintln!("Taking away write access in 10 seconds");
		sleep(Duration::from_secs(10));

		eprintln!("Now taking away write access on {:?}", pwd);
		if let Err(e) = context.sandbox.set_mount_attr_within_ns(
			&pwd,
			&MountAttributes::ro(),
			&MountAttributes::rw(),
		) {
			error!("Failed to set mount attributes: {e}");
		}
	});

	let child_result = sandbox.run_command(&mut cmd);
	handle_child_result(child_result, &context.pidfd)
}
