use std::{
	ffi::{CStr, CString},
	io,
};

use libc::FS;
use libseccomp::{ScmpFd, ScmpFilterContext, ScmpNotifData, ScmpNotifReq, ScmpSyscall};

use crate::{
	AccessRequest, AccessRequestError, Operation, TurnstileTracer, TurnstileTracerError,
	syscalls::RequestContext,
};

use log::warn;

#[derive(Debug)]
pub(crate) struct ForeignFd {
	local_fd: libc::c_int,
}

impl ForeignFd {
	pub(crate) fn from_path(path: &str) -> Result<Self, io::Error> {
		let local_fd = unsafe {
			libc::open(
				path.as_ptr() as *const libc::c_char,
				libc::O_PATH | libc::O_CLOEXEC,
				0,
			)
		};
		if local_fd < 0 {
			return Err(io::Error::last_os_error());
		}
		Ok(Self { local_fd })
	}
}

impl Drop for ForeignFd {
	fn drop(&mut self) {
		unsafe {
			libc::close(self.local_fd);
		}
	}
}

impl Clone for ForeignFd {
	fn clone(&self) -> Self {
		let duped_fd = unsafe { libc::dup(self.local_fd) };
		if duped_fd < 0 {
			panic!("Failed to dup fd: {}", io::Error::last_os_error());
		}
		Self { local_fd: duped_fd }
	}
}

/// Most filesystem syscalls on Linux accept target paths in the form of a
/// "base" fd (which may implicitly be the current working directory), and
/// a path either relative to that fd, or absolute (in which case the base
/// fd is ignored).
///
/// Since the base fd is provided by the traced process, unless it
/// provides an invalid fd, it is always guaranteed to exist.  The path,
/// however, may either point to an non-existent entry in an existing
/// directory, or a completely non-existent place even ignoring the last
/// component.
///
/// Some syscalls also accepts an empty path, in which case the target is
/// the base fd itself.
///
/// This struct preserves what was passed by the traced process, except
/// that the base fd is opened by us from /proc, and so we have a local
/// reference to the base location that will still be valid even if the
/// traced process terminates.
#[derive(Debug, Clone)]
pub struct FsTarget {
	/// None if path is absolute.
	pub(crate) dfd: Option<ForeignFd>,

	pub(crate) path: CString,
}

impl FsTarget {
	pub(crate) fn from_path(
		req: &mut RequestContext,
		path_arg_index: u8,
	) -> Result<Self, AccessRequestError> {
		let path_ptr = req.arg(path_arg_index as usize) as *const libc::c_char;
		let path = req.cstr_from_target_memory(path_ptr)?;
		let pathb = path.as_bytes();
		if pathb.len() > 0 && pathb[0] == b'/' {
			Ok(Self { dfd: None, path })
		} else {
			let cwdstr = format!("/proc/{}/cwd", req.sreq.pid);
			Ok(Self {
				dfd: Some(
					ForeignFd::from_path(&cwdstr)
						.map_err(|e| AccessRequestError::OpenFd(cwdstr, e))?,
				),
				path,
			})
		}
	}

	pub(crate) fn from_at_path(
		req: &mut RequestContext,
		dfd_arg_index: u8,
		path_arg_index: u8,
	) -> Result<Self, AccessRequestError> {
		let path_ptr = req.arg(path_arg_index as usize) as *const libc::c_char;
		let path = req.cstr_from_target_memory(path_ptr)?;
		let dfd = libc::c_int::try_from(req.arg(dfd_arg_index as usize) as i64)
			.map_err(|_| AccessRequestError::InvalidSyscallData("dfd arg not a valid c_int"))?;
		let pathb = path.as_bytes();
		if pathb.len() > 0 && pathb[0] == b'/' {
			return Ok(Self { dfd: None, path });
		}
		if dfd == libc::AT_FDCWD {
			let cwdstr = format!("/proc/{}/cwd", req.sreq.pid);
			Ok(Self {
				dfd: Some(
					ForeignFd::from_path(&cwdstr)
						.map_err(|e| AccessRequestError::OpenFd(cwdstr, e))?,
				),
				path,
			})
		} else {
			if dfd < 0 {
				Err(AccessRequestError::InvalidSyscallData("dfd invalid"))
			} else {
				let proc_fd_path = format!("/proc/{}/fd/{}", req.sreq.pid, dfd);
				Ok(Self {
					dfd: Some(
						ForeignFd::from_path(&proc_fd_path)
							.map_err(|e| AccessRequestError::OpenFd(proc_fd_path, e))?,
					),
					path,
				})
			}
		}
	}

	/// Opens the target with O_PATH.  This requires the path to actually
	/// be pointing to an existing file or directory.
	pub fn open_target(&self) -> Result<libc::c_int, io::Error> {
		unimplemented!()
	}

	/// Opens the parent of the target path with O_PATH, and returns the
	/// dir fd along with the final component of the path.  This requires
	/// everything except the final component of the path to exist (which
	/// is a normal requirement of most fs syscalls anyway).
	pub fn open_target_dir(&self) -> Result<(libc::c_int, &str), io::Error> {
		unimplemented!()
	}

	/// Return the absolute path of the target.  This requires everything
	/// except the final component of the path to exist (which is a normal
	/// requirement of most fs syscalls anyway).
	pub fn realpath(&self) -> Result<String, io::Error> {
		todo!("open_target_dir, then readlink that, then append final component")
	}
}

#[derive(Debug)]
pub struct OpenOperation {
	pub target: FsTarget,
	pub flags: libc::c_int,
}

impl OpenOperation {
	pub fn has_read(&self) -> bool {
		(self.flags & libc::O_RDONLY != 0 || self.flags & libc::O_RDWR != 0)
			&& self.flags & libc::O_WRONLY == 0
			&& self.flags & libc::O_PATH == 0
	}

	pub fn has_write(&self) -> bool {
		(self.flags & libc::O_WRONLY != 0 || self.flags & libc::O_RDWR != 0)
			&& self.flags & libc::O_RDONLY == 0
			&& self.flags & libc::O_PATH == 0
	}
}

#[derive(Debug)]
pub struct CreateOperation {
	pub target: FsTarget,
	pub mode: libc::mode_t,
	pub kind: CreateKind,
}

#[derive(Debug)]
pub enum CreateKind {
	File,
	Directory,
	Symlink { target: String },
	Device { dev: libc::dev_t },
}

#[derive(Debug)]
pub struct RenameOperation {
	pub from: FsTarget,
	pub to: FsTarget,
	pub exchange: bool,
}

#[derive(Debug)]
pub struct UnlinkOperation {
	pub target: FsTarget,
	pub dir: bool,
}

#[derive(Debug)]
pub struct LinkOperation {
	pub from: FsTarget,
	pub to: FsTarget,
	pub follow_src_symlink: bool,
}

#[derive(Debug)]
pub struct ExecOperation {
	pub target: FsTarget,
}

type SyscallHandler1 = fn(
	req: &mut RequestContext,
	target: &FsTarget,
) -> Result<(Operation, Option<Operation>), AccessRequestError>;

type SyscallHandler2 = fn(
	req: &mut RequestContext,
	target1: &FsTarget,
	target2: &FsTarget,
) -> Result<(Operation, Option<Operation>), AccessRequestError>;

type SyscallHandlerCustom =
	fn(req: &mut RequestContext) -> Result<(Operation, Option<Operation>), AccessRequestError>;

// See https://syscalls.mebeim.net

fn handle_open_like(
	req: &mut RequestContext,
	target: &FsTarget,
	create_mode: Option<libc::mode_t>,
	openat_flags: Option<u64>,
	access_mode: Option<u64>,
	openat2_resolve: Option<u64>,
) -> Result<(Operation, Option<Operation>), AccessRequestError> {
	todo!(
		"Return the right Operation. For O_CREAT, return two operations - first an FsCreate, then FsOpen"
	)
}

fn handle_openat2(
	req: &mut RequestContext,
	target: &FsTarget,
) -> Result<(Operation, Option<Operation>), AccessRequestError> {
	let open_how_ptr = req.arg(2) as *const libc::open_how;
	let open_how = unsafe { req.value_from_target_memory(open_how_ptr) }?;
	handle_open_like(
		req,
		target,
		Some(open_how.mode as libc::mode_t),
		Some(open_how.flags),
		None,
		Some(open_how.resolve),
	)
}

fn handle_create_like(
	req: &mut RequestContext,
	target: &FsTarget,
	mode: libc::mode_t,
	kind: CreateKind,
	symlink_from_arg_index: Option<u8>,
	dev_t_arg_index: Option<u8>,
) -> Result<(Operation, Option<Operation>), AccessRequestError> {
	unimplemented!()
}

// (name, handler, arg index of the path)
const FS_SYSCALLS_PATH: &'static [(&'static str, SyscallHandler1, u8)] = &[
	(
		"open",
		|req, target| {
			handle_open_like(
				req,
				target,
				Some(req.arg(2) as libc::mode_t),
				Some(req.arg(1)),
				Some(req.arg(2)),
				None,
			)
		},
		0,
	),
	(
		"access",
		|req, target| handle_open_like(req, target, None, None, Some(req.arg(1)), None),
		0,
	),
	("mkdir", |req, target| unimplemented!(), 0),
	("rmdir", |req, target| unimplemented!(), 0),
	(
		"creat",
		|req, target| {
			handle_open_like(
				req,
				target,
				Some(req.arg(1) as libc::mode_t),
				None,
				None,
				None,
			)
		},
		0,
	),
	("mknod", |req, target| unimplemented!(), 0),
	("unlink", |req, target| unimplemented!(), 0),
	(
		"execve",
		|req, target| handle_open_like(req, target, None, None, Some(libc::X_OK as u64), None),
		0,
	),
	// The "source" of a symlink is arbitrary data, so we don't treat it as a FsTarget.
	("symlink", |req, target| unimplemented!(), 1),
];

// (name, handler, arg index of the dfd, arg index of the path)
// todo: for this table and the other at table, we should have a few extra
// fields to denote where to (if at all) find the AT_EMPTY_PATH and
// AT_SYMLINK_NOFOLLOW flags - i.e. a non-negative arg index if we should
// try to find the flag in the syscall arguments, or -1 if not.
const FS_SYSCALLS_DFD_PATH: &'static [(&'static str, SyscallHandler1, u8, u8)] = &[
	(
		"openat",
		|req, target| {
			handle_open_like(
				req,
				target,
				Some(req.arg(3) as libc::mode_t),
				Some(req.arg(2)),
				None,
				None,
			)
		},
		0,
		1,
	),
	("openat2", handle_openat2, 0, 1),
	(
		"faccessat",
		|req, target| handle_open_like(req, target, None, None, Some(req.arg(2)), None),
		0,
		1,
	),
	(
		"faccessat2",
		|req, target| handle_open_like(req, target, None, Some(req.arg(3)), Some(req.arg(2)), None),
		0,
		1,
	),
	// The "source" of a symlink is arbitrary data, so we don't treat it as a FsTarget.
	("symlinkat", |req, target| unimplemented!(), 1, 2),
	("unlinkat", |req, target| unimplemented!(), 0, 1),
	("mkdirat", |req, target| unimplemented!(), 0, 1),
	("mknodat", |req, target| unimplemented!(), 0, 1),
	(
		"execveat",
		|req, target| handle_open_like(req, target, None, None, Some(libc::X_OK as u64), None),
		0,
		1,
	),
];
// (name, handler, arg index of the first path, arg index of the second path)
const FS_SYSCALLS_PATH_PATH: &'static [(&'static str, SyscallHandler2, u8, u8)] = &[
	("rename", |req, target1, target2| unimplemented!(), 0, 1),
	("link", |req, target1, target2| unimplemented!(), 0, 1),
];
// (name, handler, arg index of the first dfd, arg index of the first path, arg index of the second dfd, arg index of the second path)
const FS_SYSCALLS_DFD_PATH_DFD_PATH: &'static [(&'static str, SyscallHandler2, u8, u8, u8, u8)] = &[
	(
		"renameat",
		|req, target1, target2| unimplemented!(),
		0,
		1,
		2,
		3,
	),
	(
		"renameat2",
		|req, target1, target2| unimplemented!(),
		0,
		1,
		2,
		3,
	),
	(
		"linkat",
		|req, target1, target2| unimplemented!(),
		0,
		1,
		2,
		3,
	),
];

pub(crate) fn add_filter_rules(
	filter_ctx: &mut ScmpFilterContext,
) -> Result<(), TurnstileTracerError> {
	for list in &[
		FS_SYSCALLS_PATH
			.into_iter()
			.map(|(name, _, _)| *name)
			.collect::<Vec<_>>(),
		FS_SYSCALLS_DFD_PATH
			.into_iter()
			.map(|(name, _, _, _)| *name)
			.collect::<Vec<_>>(),
		FS_SYSCALLS_PATH_PATH
			.into_iter()
			.map(|(name, _, _, _)| *name)
			.collect::<Vec<_>>(),
		FS_SYSCALLS_DFD_PATH_DFD_PATH
			.into_iter()
			.map(|(name, _, _, _, _, _)| *name)
			.collect::<Vec<_>>(),
	] {
		for name in list {
			let scmpc = ScmpSyscall::from_name(name)
				.map_err(|e| TurnstileTracerError::ResolveSyscall(name, e))?;
			filter_ctx
				.add_rule(libseccomp::ScmpAction::Notify, scmpc)
				.map_err(|e| TurnstileTracerError::AddRule(name, e))?;
		}
	}
	Ok(())
}

pub(crate) fn handler_return_to_access_req(ret: (Operation, Option<Operation>)) -> AccessRequest {
	let mut ar = AccessRequest {
		operations: vec![ret.0],
	};
	if let Some(extra_op) = ret.1 {
		ar.operations.push(extra_op);
	}
	ar
}

pub(crate) fn handle_notification<'a>(
	request_ctx: &mut RequestContext<'a>,
) -> Result<Option<AccessRequest>, AccessRequestError> {
	let sreq = request_ctx.sreq;

	// todo: we really shouldn't be allocating and comparing strings on
	// this path.  Optimize this later (which will likely require
	// refactoring the above tables - maybe they need to be constructed at
	// runtime with resolved syscall numbers).
	let sysc = match sreq.data.syscall.get_name() {
		Ok(name) => name,
		Err(_) => {
			// todo: warn
			return Ok(None);
		}
	};

	for &(name, handler, path_arg_index) in FS_SYSCALLS_PATH {
		if sysc == name {
			let target = FsTarget::from_path(request_ctx, path_arg_index)?;
			let (op, extra_op) = handler(request_ctx, &target)?;
			return Ok(Some(handler_return_to_access_req((op, extra_op))));
		}
	}

	for &(name, handler, dfd_arg_index, path_arg_index) in FS_SYSCALLS_DFD_PATH {
		if sysc == name {
			let target = FsTarget::from_at_path(request_ctx, dfd_arg_index, path_arg_index)?;
			let (op, extra_op) = handler(request_ctx, &target)?;
			return Ok(Some(handler_return_to_access_req((op, extra_op))));
		}
	}

	for &(name, handler, path1_arg_index, path2_arg_index) in FS_SYSCALLS_PATH_PATH {
		if sysc == name {
			let target1 = FsTarget::from_path(request_ctx, path1_arg_index)?;
			let target2 = FsTarget::from_path(request_ctx, path2_arg_index)?;
			let (op, extra_op) = handler(request_ctx, &target1, &target2)?;
			return Ok(Some(handler_return_to_access_req((op, extra_op))));
		}
	}

	for &(name, handler, dfd1_arg_index, path1_arg_index, dfd2_arg_index, path2_arg_index) in
		FS_SYSCALLS_DFD_PATH_DFD_PATH
	{
		if sysc == name {
			let target1 = FsTarget::from_at_path(request_ctx, dfd1_arg_index, path1_arg_index)?;
			let target2 = FsTarget::from_at_path(request_ctx, dfd2_arg_index, path2_arg_index)?;
			let (op, extra_op) = handler(request_ctx, &target1, &target2)?;
			return Ok(Some(handler_return_to_access_req((op, extra_op))));
		}
	}

	warn!("Unhandled syscall: {}", sysc);
	Ok(None)
}
