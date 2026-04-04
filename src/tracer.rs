use core::panic;
use std::{
	ffi::CStr,
	os::unix::process::CommandExt,
	sync::{Mutex, OnceLock},
	thread,
};

use libseccomp::{ScmpArch, ScmpFd, ScmpFilterContext, ScmpNotifReq};
use libseccomp_sys::scmp_filter_ctx;

use crate::{
	AccessRequest, AccessRequestError, TurnstileTracerError,
	fs::ForeignFd,
	syscalls::{self, RequestContext},
	utils::{unix_recv_fd, unix_send_fd},
};

use log::{error, warn};

fn dump_seccomp_request(req: &ScmpNotifReq) -> String {
	let comm = std::fs::read_to_string(format!("/proc/{}/comm", req.pid))
		.ok()
		.map(|s| s.trim().to_string())
		.unwrap_or_else(|| "???".to_string());
	format!(
		"process: {}[{}]\nsyscall: {} ({})\nargs: [{:#x}, {:#x}, {:#x}, {:#x}, {:#x}, {:#x}]",
		comm,
		req.pid,
		req.data.syscall.get_name().unwrap_or("???".to_string()),
		req.data.syscall.as_raw_syscall(),
		req.data.args[0],
		req.data.args[1],
		req.data.args[2],
		req.data.args[3],
		req.data.args[4],
		req.data.args[5],
	)
}

/// Implements a seccomp-unotify-based access tracer.
///
/// <div class="warning">
/// Seccomp-unotify is not a sandboxing solution on its own due to the
/// limitations of syscall-based filtering (such as TOCTOU problems with
/// memory references).  This struct does not provide any security when
/// used alone.
/// </div>
#[derive(Debug)]
pub struct TurnstileTracer {
	/// Stores the seccomp filter context.
	pub filter_ctx: Mutex<ScmpFilterContext>,

	/// Raw pointer into the filter context for use in pre_exec-safe code.
	/// Valid for as long as `filter_ctx` is alive (i.e., for the lifetime
	/// of this struct).
	filter_ctx_raw: SendableContextPtr,

	/// Stores the notify fd.
	///
	/// Seccomp only gives us the notification fd at filter load time.
	/// Therefore this is unset until [`Self::install_filters`] or
	/// [`Self::run_command`] is called.
	pub notify_fd: OnceLock<ScmpFd>,

	/// Unix socket pair used to transfer the notify fd from a child
	/// process to the parent.  Index 0 is the parent (receiving) end and
	/// index 1 is the child (sending) end.  Created in [`Self::new`] and
	/// consumed (closed) by [`Self::install_filters`] and
	/// [`Self::receive_notify_fd`].
	pub(crate) notify_fd_sock_pair: [libc::c_int; 2],
}

unsafe impl Sync for TurnstileTracer {}
unsafe impl Send for TurnstileTracer {}

impl TurnstileTracer {
	pub fn new() -> Result<Self, TurnstileTracerError> {
		let mut filter_ctx = ScmpFilterContext::new(libseccomp::ScmpAction::Allow)
			.map_err(TurnstileTracerError::Init)?;
		let native_arch = ScmpArch::native();
		filter_ctx
			.add_arch(native_arch)
			.map_err(TurnstileTracerError::AddArch)?;

		syscalls::fs::add_filter_rules(&mut filter_ctx)?;
		syscalls::net::add_filter_rules(&mut filter_ctx)?;

		let filter_ctx_raw = SendableContextPtr(filter_ctx.as_ptr());

		let mut notify_fd_sock_pair = [-1i32; 2];
		unsafe {
			if libc::socketpair(
				libc::AF_UNIX,
				libc::SOCK_STREAM | libc::SOCK_CLOEXEC,
				0,
				notify_fd_sock_pair.as_mut_ptr(),
			) != 0
			{
				return Err(TurnstileTracerError::Socketpair(
					std::io::Error::last_os_error(),
				));
			}
		}

		Ok(Self {
			filter_ctx: Mutex::new(filter_ctx),
			filter_ctx_raw,
			notify_fd: OnceLock::new(),
			notify_fd_sock_pair,
		})
	}

	/// Process Seccomp notifications and possibly return an access
	/// request (or None if, for example, the syscall accesses an ignored
	/// file).
	///
	/// If an [`AccessRequest`](crate::AccessRequest) along with its
	/// [`RequestContext`](crate::RequestContext) is returned, the traced
	/// process is paused, and the caller should respond to the request by
	/// calling either
	/// [`RequestContext::send_continue`](crate::RequestContext::send_continue)
	/// or
	/// [`RequestContext::send_error`](crate::RequestContext::send_error).
	/// If None is returned, the tracer is set to continue automatically.
	/// The traced process is also resumed if the returned
	/// [`RequestContext`](crate::RequestContext) is dropped.
	///
	/// If the caller leaks the returned
	/// [`RequestContext`](crate::RequestContext) without responding to
	/// it, the traced process will be paused indefinitely until it
	/// receives a signal.
	///
	/// Blocks until the notify_fd is ready if it is not.
	pub fn yield_request<'a>(
		&'a self,
	) -> Result<Option<(AccessRequest, RequestContext<'a>)>, AccessRequestError> {
		let notify_fd = *self.notify_fd.wait();
		let req = ScmpNotifReq::receive(notify_fd).map_err(AccessRequestError::NotifyReceive)?;
		let procmem = format!("/proc/{}/mem\0", req.pid);
		let mut ctx = RequestContext {
			_tracer: self,
			sreq: req,
			notify_fd,
			valid: true,
			mem_fd: ForeignFd::from_path_with_flags(
				CStr::from_bytes_with_nul(procmem.as_bytes()).unwrap(),
				libc::O_RDONLY | libc::O_CLOEXEC,
			)
			.map_err(|e| AccessRequestError::ReadProcessMemoryOpen(req.pid, e))?,
		};
		let result = self.handle_notification(&mut ctx);
		match result {
			Ok(Some(access_req)) => {
				if ctx.still_valid()? == false {
					// If the notification is no longer valid, then we
					// don't want to emit the access request (which might
					// have been constructed out of invalid data)
					return Ok(None);
				}
				Ok(Some((access_req, ctx)))
			}
			Ok(None) => {
				ctx.send_continue()?;
				Ok(None)
			}
			Err(e) => {
				// If the notification is no longer valid, then we ignore
				// any errors encountered while processing it.
				if ctx.still_valid().is_ok_and(|v| v == false) {
					Ok(None)
				} else {
					let cont_err = ctx.send_continue();
					if let AccessRequestError::InvalidSyscallData(s) = e {
						warn!(
							"Got invalid syscall for request:\n{}\nError: {}",
							dump_seccomp_request(&ctx.sreq),
							s
						);
					} else {
						error!(
							"Error while handling seccomp notification:\nRequest: \n{}\nError: {:#?}",
							dump_seccomp_request(&ctx.sreq),
							e
						);
					}
					if let Err(e) = cont_err {
						error!("failed to send continue response: {:#?}", e);
					}
					Err(e)
				}
			}
		}
	}

	fn handle_notification<'a>(
		&'a self,
		req_ctx: &mut RequestContext<'a>,
	) -> Result<Option<AccessRequest>, AccessRequestError> {
		if let Some(req) = syscalls::fs::handle_notification(req_ctx)? {
			return Ok(Some(req));
		}
		if let Some(req) = syscalls::net::handle_notification(req_ctx)? {
			return Ok(Some(req));
		}
		return Ok(None);
	}

	/// Load the seccomp filter into the current process or a forked child.
	///
	/// When `send_to_parent` is `false`, the filter is installed in the
	/// current process and [`Self::notify_fd`] is set.
	///
	/// When `send_to_parent` is `true`, this function is intended to be
	/// called inside a `pre_exec` hook (i.e. after `fork()` but before
	/// `exec()`).  It loads the filter, sends the resulting notify fd to
	/// the parent via the child side of [`Self::notify_fd_sock_pair`], and
	/// then closes the notify fd.  The parent should call
	/// [`Self::receive_notify_fd`] to receive the notify fd.  This path is
	/// async-signal-safe: seccomp errors cause a `panic!` and a
	/// [`TurnstileTracerError::SendNotifyFd`] is returned only if the
	/// socket send fails.
	///
	/// In both cases, both ends of [`Self::notify_fd_sock_pair`] are closed
	/// unconditionally.
	pub fn install_filters(&self, send_to_parent: bool) -> Result<(), TurnstileTracerError> {
		let parent_sock = self.notify_fd_sock_pair[0];
		let child_sock = self.notify_fd_sock_pair[1];

		if send_to_parent {
			// pre_exec-safe: only async-signal-safe operations.
			// Seccomp errors use panic!(); only unix_send_fd failure is
			// returned as an Err.
			unsafe {
				libc::close(parent_sock);

				let scmpctx_ptr = self.filter_ctx_raw.into_ptr();
				let rc = libseccomp_sys::seccomp_load(scmpctx_ptr);
				if rc != 0 {
					panic!("seccomp_load failed with error code {}", rc);
				}
				let notify_fd_val = libseccomp_sys::seccomp_notify_fd(scmpctx_ptr);
				if notify_fd_val < 0 {
					panic!(
						"seccomp_notify_fd failed with error code {}",
						-1 * notify_fd_val
					);
				}

				let send_result = unix_send_fd(child_sock, notify_fd_val)
					.map_err(TurnstileTracerError::SendNotifyFd);
				libc::close(child_sock);
				libc::close(notify_fd_val);
				send_result?;
			}
		} else {
			if self.notify_fd.get().is_some() {
				panic!("Seccomp filters already loaded elsewhere");
			}

			let filter_ctx = self.filter_ctx.lock().unwrap();
			let load_result = filter_ctx.load().map_err(TurnstileTracerError::Load);
			if load_result.is_err() {
				unsafe {
					libc::close(parent_sock);
					libc::close(child_sock);
				}
				return load_result;
			}
			let notify_fd_result = filter_ctx
				.get_notify_fd()
				.map_err(TurnstileTracerError::NotifyFd);
			unsafe {
				libc::close(parent_sock);
				libc::close(child_sock);
			}
			let notify_fd_val = notify_fd_result?;
			self.notify_fd.set(notify_fd_val).unwrap_or_else(|_| {
				// This can only happen if we race with another thread
				// also trying to load the filters
				panic!("Seccomp filters already loaded elsewhere");
			});
		}
		Ok(())
	}

	/// Receive the notify fd sent by a child process that called
	/// [`Self::install_filters`] with `send_to_parent: true`.
	///
	/// Recvs from the parent side of [`Self::notify_fd_sock_pair`], closes
	/// that end of the socket, and stores the received fd in
	/// [`Self::notify_fd`].
	pub fn receive_notify_fd(&self) -> Result<(), TurnstileTracerError> {
		let parent_sock = self.notify_fd_sock_pair[0];
		let recv_res = unix_recv_fd(parent_sock);
		unsafe {
			libc::close(parent_sock);
		}
		let received_fd = recv_res.map_err(TurnstileTracerError::ReceiveNotifyFd)?;
		self.notify_fd.set(received_fd).unwrap_or_else(|_| {
			// This can only happen if we race with another thread
			// also trying to load the filters
			panic!("Seccomp filters already loaded elsewhere");
		});
		Ok(())
	}

	/// Spawn a child process with the seccomp filters installed.
	///
	/// The caller should arrange to process notifications via
	/// [`Self::yield_request`] on another thread before calling this, as
	/// this function will block until the execve() is done, which will
	/// require the caller to allow the file access to continue.
	///
	/// Should the caller wish to do more complex setup in the pre_exec
	/// stage, [`Command::pre_exec`](std::process::Command::pre_exec) can
	/// be used to install more pre_exec hooks that will be called before
	/// the seccomp filters are loaded.
	pub fn run_command(
		&self,
		cmd: &mut std::process::Command,
	) -> Result<std::process::Child, TurnstileTracerError> {
		if self.notify_fd.get().is_some() {
			panic!("Seccomp filters already loaded elsewhere");
		}

		let child_sock = self.notify_fd_sock_pair[1];
		// Cast to usize so the closure is 'static + Send (raw pointers are neither).
		// Safety: self outlives the pre_exec closure, which is called during
		// cmd.spawn() while we still hold &self.
		let self_ptr = self as *const TurnstileTracer as usize;
		unsafe {
			cmd.pre_exec(move || {
				// Everything in this function must be async-signal-safe.
				// Safety: self outlives the pre_exec closure (called during
				// cmd.spawn() while &self is held), and TurnstileTracer is
				// Sync so shared access from this thread is sound.
				let tracer = &*(self_ptr as *const TurnstileTracer);
				tracer.install_filters(true).map_err(|e| match e {
					TurnstileTracerError::SendNotifyFd(io_err) => io_err,
					// All other error paths in install_filters(true) panic,
					// so this branch is unreachable.
					_ => unreachable!(),
				})?;
				Ok(())
			});
		}

		thread::scope(|s| -> Result<std::process::Child, TurnstileTracerError> {
			let jh = s.spawn(|| -> Result<(), TurnstileTracerError> {
				self.receive_notify_fd()
			});
			let spawn_res = cmd.spawn();
			unsafe {
				// Doing this will unblock the receiver thread if spawn()
				// fails before the notify fd is sent.
				libc::close(child_sock);
			}
			match spawn_res {
				Ok(child) => {
					jh.join().expect("receiver thread panicked")?;
					Ok(child)
				}
				Err(e) => {
					let _ = jh.join();
					Err(TurnstileTracerError::Spawn(e))
				}
			}
		})
	}
}

#[derive(Copy, Clone, Debug)]
struct SendableContextPtr(scmp_filter_ctx);
unsafe impl Send for SendableContextPtr {}
unsafe impl Sync for SendableContextPtr {}
impl SendableContextPtr {
	fn into_ptr(self) -> scmp_filter_ctx {
		self.0
	}
}
