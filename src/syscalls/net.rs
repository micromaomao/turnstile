use std::{ffi::CStr, mem::offset_of};

use libseccomp::{ScmpFilterContext, ScmpSyscall};

use crate::{
	AccessRequest, AccessRequestError, Operation, TurnstileTracerError,
	syscalls::{RequestContext, fs::ForeignFd, fs::FsTarget, lazy_syscall_table_name_to_number},
};

/// Unix socket syscalls to intercept:
/// (name, operation builder, addr arg index, addrlen arg index).
const UNIX_SOCK_SYSCALLS: &[(&str, fn(FsTarget) -> Operation, u8, u8)] = &[
	("connect", |t| Operation::UnixConnect(t), 1, 2),
	("bind", |t| Operation::UnixListen(t), 1, 2),
	("sendto", |t| Operation::UnixSendto(t), 4, 5),
	("recvfrom", |t| Operation::UnixRecvfrom(t), 4, 5),
];

lazy_syscall_table_name_to_number!(
	UNIX_SOCK_SYSCALLS,
	resolved_unix_sock_syscalls,
	fn(FsTarget) -> Operation,
	u8,
	u8
);

pub(crate) fn add_filter_rules(
	filter_ctx: &mut ScmpFilterContext,
) -> Result<(), TurnstileTracerError> {
	for &(name, _, _, _) in UNIX_SOCK_SYSCALLS {
		let scmpc = ScmpSyscall::from_name(name)
			.map_err(|e| TurnstileTracerError::ResolveSyscall(name, e))?;
		filter_ctx
			.add_rule(libseccomp::ScmpAction::Notify, scmpc)
			.map_err(|e| TurnstileTracerError::AddRule(name, e))?;
	}
	Ok(())
}

/// Try to read a Unix socket target from the traced process's memory.
/// Returns `None` if the address is null, too short, or is an abstract-
/// namespace socket (no filesystem path).
fn read_unix_target(
	req: &mut RequestContext,
	addr_arg: usize,
	addrlen_arg: usize,
) -> Result<Option<FsTarget>, AccessRequestError> {
	let addr_ptr = req.arg(addr_arg) as usize;
	if addr_ptr == 0 {
		return Ok(None);
	}
	let addrlen = req.arg(addrlen_arg) as usize;
	// We need at least sa_family (2 bytes) + 1 path byte.
	if addrlen < 3 {
		return Ok(None);
	}

	// Read the address family (first 2 bytes of sockaddr).  We have to do
	// this separately from reading the path because the target sockaddr
	// might not in fact be a sockaddr_un, and it might be smaller.  If
	// the allocated sockaddr is small and crosses a page boundary, we
	// don't want to read out-of-bound.
	let family = req.value_from_target_memory(
		(addr_ptr + offset_of!(libc::sockaddr_un, sun_family)) as *const libc::sa_family_t,
	)?;
	if family != libc::AF_UNIX as libc::sa_family_t {
		return Ok(None);
	}

	let sun_path_ptr = (addr_ptr + offset_of!(libc::sockaddr_un, sun_path)) as *const libc::c_char;
	let path = req.cstr_from_target_memory(sun_path_ptr)?;

	// Abstract-namespace sockets have a sun_path with the first byte
	// being NUL, which we will end up reading as an empty string.
	if path.as_bytes().is_empty() {
		return Ok(None);
	}

	let target = if path.as_bytes().first() == Some(&b'/') {
		FsTarget {
			dfd: None,
			path,
			no_follow: false,
		}
	} else {
		let cwdstr = format!("/proc/{}/cwd\0", req.sreq.pid);
		FsTarget {
			dfd: Some(
				ForeignFd::from_path(CStr::from_bytes_with_nul(cwdstr.as_bytes()).unwrap())
					.map_err(|e| AccessRequestError::OpenFd(cwdstr, e))?,
			),
			path,
			no_follow: false,
		}
	};
	Ok(Some(target))
}

pub(crate) fn handle_notification<'a>(
	request_ctx: &mut RequestContext<'a>,
) -> Result<Option<AccessRequest>, AccessRequestError> {
	let syscall = request_ctx.sreq.data.syscall;

	for &(scmp, builder, addr_arg, addrlen_arg) in resolved_unix_sock_syscalls() {
		if syscall != scmp {
			continue;
		}
		if let Some(target) =
			read_unix_target(request_ctx, addr_arg as usize, addrlen_arg as usize)?
		{
			let op = builder(target);
			return Ok(Some(AccessRequest {
				operations: vec![op],
			}));
		}
		// Not a Unix socket or no address — let the kernel handle it.
		return Ok(None);
	}

	Ok(None)
}
