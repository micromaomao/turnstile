use std::io;

use libseccomp::{ScmpFd, ScmpNotifReq, ScmpNotifResp, ScmpNotifRespFlags};

use crate::{AccessRequestError, TurnstileTracer, syscalls::fs::ForeignFd};

pub mod fs;
pub mod net;

#[derive(Debug)]
pub struct RequestContext<'a> {
	pub(crate) tracer: &'a TurnstileTracer,
	pub(crate) sreq: ScmpNotifReq,
	pub(crate) notify_fd: ScmpFd,
	pub(crate) valid: bool,
	pub(crate) mem_fd: ForeignFd,
}

impl<'a> RequestContext<'a> {
	pub fn sreq(&self) -> &ScmpNotifReq {
		&self.sreq
	}

	pub fn arg(&self, index: usize) -> u64 {
		self.sreq.data.args[index]
	}

	pub(crate) fn still_valid(&mut self) -> Result<bool, AccessRequestError> {
		if !self.valid {
			return Ok(false);
		}
		match libseccomp::notify_id_valid(self.notify_fd, self.sreq.id) {
			Ok(()) => Ok(true),
			Err(e) => {
				if e.errno() == Some(libseccomp::error::SeccompErrno::ENOENT) {
					self.valid = false;
					Ok(false)
				} else {
					Err(AccessRequestError::NotifyIdValid(e))
				}
			}
		}
	}

	pub(crate) fn send_response(
		&mut self,
		resp: libseccomp::ScmpNotifResp,
	) -> Result<(), AccessRequestError> {
		if self.valid {
			resp.respond(self.notify_fd)
				.map_err(AccessRequestError::NotifyRespond)?;
			self.valid = false;
		}
		Ok(())
	}

	pub fn send_continue(&mut self) -> Result<(), AccessRequestError> {
		self.send_response(ScmpNotifResp::new_continue(
			self.sreq.id,
			ScmpNotifRespFlags::empty(),
		))
	}

	/// Users are reminded that this should not be used to deny access
	/// unless there is a separate sandboxing mechanism making sure that
	/// the access would be denied should the traced process attempt to
	/// modify any path buffers from another thread.
	pub fn send_error(&mut self, errno: libc::c_int) -> Result<(), AccessRequestError> {
		self.send_response(ScmpNotifResp::new_error(
			self.sreq.id,
			errno,
			ScmpNotifRespFlags::empty(),
		))
	}

	pub(crate) fn cstr_from_target_memory(
		&mut self,
		src: *const libc::c_char,
	) -> Result<std::ffi::CString, AccessRequestError> {
		todo!(
			"seek mem_fd, read for ALIGN_UP(addr + 1, PAGE_SIZE) bytes, if NUL byte found then return CString, else read another page and find NUL byte.  If NUL byte still not found, return InvalidSyscallData(\"provided path string exceeds PATH_MAX\")"
		)
	}

	pub(crate) fn value_from_target_memory<T: Copy>(
		&mut self,
		src: *const T,
	) -> Result<T, AccessRequestError> {
		todo!("seek mem_fd, read sizeof(T) bytes");
	}
}

impl Drop for RequestContext<'_> {
	fn drop(&mut self) {
		if self.still_valid().is_ok_and(|v| v) {
			// todo: warn that RequestContext dropped without sending a response
			_ = self.send_continue();
		}
	}
}
