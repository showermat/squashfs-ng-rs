//! This crate provides Rust bindings for the [squashfs-tools-ng][] library, providing support for
//! SquashFS as an embeddable archive format without the need for kernel support.  It also tries to
//! provide a level of safety and abstraction on top of the C library.  Cross-platform usability is a
//! secondary goal.
//!
//! # Installation
//!
//! Currently, the underlying [squashfs-tools-ng][] library must be installed on the system both to
//! build and to use this library.  The development headers (`/usr/include/sqfs/...`) are required
//! to build, and the shared library (`/usr/lib/libsquashfs.so`) to run.  The project's GitHub page
//! asserts that packages are available in many Linux distributions' repositories.
//!
//! Once the dependencies are in place, this should function like most other Rust libraries, and
//! `cargo build` should suffice to build the library.
//!
//! # Usage
//!
//! The [`read`] and [`write`](module@write) modules below provide support for reading and writing
//! SquashFS files, respectively.  Check them out for further documentation.
//!
//! [squashfs-tools-ng]: https://github.com/AgentD/squashfs-tools-ng/

#[macro_use] extern crate lazy_static;
extern crate libc;
extern crate memmap;
extern crate num_derive;
extern crate num_traits;
extern crate owning_ref;
extern crate walkdir;
extern crate xattr;

use std::mem::MaybeUninit;
use std::ffi::{OsStr, OsString};
use std::path::PathBuf;
use std::ptr;
use num_derive::FromPrimitive;
use num_traits::FromPrimitive;
use thiserror::Error;

mod bindings {
	#![allow(non_camel_case_types)]
	#![allow(non_snake_case)]
	#![allow(non_upper_case_globals)]
	#![allow(dead_code)]
	include!(concat!(env!("OUT_DIR"), "/bindings.rs"));
}

use bindings::*;

pub mod read;
pub mod write;

type BoxedError = Box<dyn std::error::Error + std::marker::Send + std::marker::Sync>;

/// Errors raised by the underlying library.
///
/// This error type reflects all errors raised by the squashfs-tools-ng library.  This should
/// always be wrapped in a [`SquashfsError`] before being returned from any of the functions in
/// this library.
#[derive(Error, Debug, FromPrimitive)]
#[repr(i32)]
pub enum LibError {
	#[error("Failed to allocate memory")] Alloc = SQFS_ERROR_SQFS_ERROR_ALLOC,
	#[error("Generic I/O failure")] Io = SQFS_ERROR_SQFS_ERROR_IO,
	#[error("Compressor failed to extract data")] Compressor = SQFS_ERROR_SQFS_ERROR_COMPRESSOR,
	#[error("Internal error")] Internal = SQFS_ERROR_SQFS_ERROR_INTERNAL,
	#[error("Archive file appears to be corrupted")] Corrupted = SQFS_ERROR_SQFS_ERROR_CORRUPTED,
	#[error("Unsupported feature used")] Unsupported = SQFS_ERROR_SQFS_ERROR_UNSUPPORTED,
	#[error("Archive would overflow memory")] Overflow = SQFS_ERROR_SQFS_ERROR_OVERFLOW,
	#[error("Out-of-bounds access attempted")] OutOfBounds = SQFS_ERROR_SQFS_ERROR_OUT_OF_BOUNDS,
	#[error("Superblock magic number incorrect")] SuperMagic = SQFS_ERROR_SFQS_ERROR_SUPER_MAGIC,
	#[error("Unsupported archive version")] SuperVersion = SQFS_ERROR_SFQS_ERROR_SUPER_VERSION,
	#[error("Archive block size is invalid")] SuperBlockSize = SQFS_ERROR_SQFS_ERROR_SUPER_BLOCK_SIZE,
	#[error("Not a directory")] NotDir = SQFS_ERROR_SQFS_ERROR_NOT_DIR,
	#[error("Path does not exist")] NoEntry = SQFS_ERROR_SQFS_ERROR_NO_ENTRY,
	#[error("Hard link loop detected")] LinkLoop = SQFS_ERROR_SQFS_ERROR_LINK_LOOP,
	#[error("Not a regular file")] NotFile = SQFS_ERROR_SQFS_ERROR_NOT_FILE,
	#[error("Invalid argument passed")] ArgInvalid = SQFS_ERROR_SQFS_ERROR_ARG_INVALID,
	#[error("Library operations performed in incorrect order")] Sequence = SQFS_ERROR_SQFS_ERROR_SEQUENCE,
}

/// Errors encountered while reading or writing an archive.
///
/// This wraps all errors that might be encountered by the library during its normal course of
/// operation.
#[derive(Error, Debug)]
pub enum SquashfsError {
	#[error("Input contains an invalid null character")] NullInput(#[from] std::ffi::NulError),
	#[error("Encoded string is not valid UTF-8")] Utf8(#[from] std::string::FromUtf8Error),
	#[error("OS string is not valid UTF-8")] OsUtf8(OsString),
	#[error("{0}: {1}")] LibraryError(String, LibError),
	#[error("{0}: Unknown error {1} in SquashFS library")] UnknownLibraryError(String, i32),
	#[error("{0}: Squashfs library did not return expected value")] LibraryReturnError(String),
	#[error("{0}")] LibraryNullError(String),
	#[error("Symbolic link chain exceeds {0} elements")] LinkChain(i32), // Can I use a const in the formatting string?
	#[error("Symbolic link loop detected containing {0}")] LinkLoop(PathBuf),
	#[error("Dangling symbolic link from {0} to {1}")] DanglingLink(PathBuf, PathBuf),
	#[error("{0} is type {1}, not {2}")] WrongType(String, String, String),
	#[error("Tried to copy an object that can't be copied")] Copy,
	#[error("Tried to get parent of a node with an unknown path")] NoPath,
	#[error("Inode index {0} is not within limits 1..{1}")] Range(u64, u64),
	#[error("Couldn't read file: {0}")] Read(#[from] std::io::Error),
	#[error("The filesystem does not support the feature: {0}")] Unsupported(String),
	#[error("Memory mapping failed: {0}")] Mmap(std::io::Error),
	#[error("Couldn't get the current system time: {0}")] Time(#[from] std::time::SystemTimeError),
	#[error("Refusing to create empty archive")] Empty,
	#[error("Tried to write parent directory before child node {0}")] WriteOrder(u32),
	#[error("Tried to write unknown or unsupported file type")] WriteType(std::fs::FileType),
	#[error("Callback returned an error")] WrappedError(BoxedError),
	#[error("Failed to retrieve xattrs for {0}: {1}")] Xattr(PathBuf, std::io::Error),
	#[error("Tried to add files to a writer that was already finished")] Finished,
	#[error("Internal error: {0}")] Internal(String),
}

/// Result type returned by SquashFS library operations.
pub type Result<T> = std::result::Result<T, SquashfsError>;

fn sfs_check(code: i32, desc: &str) -> Result<i32> {
	match code {
		i if i >= 0 => Ok(i),
		i => match FromPrimitive::from_i32(i) {
			Some(e) => Err(SquashfsError::LibraryError(desc.to_string(), e)),
			None => Err(SquashfsError::UnknownLibraryError(desc.to_string(), i)),
		}
	}
}

fn sfs_destroy<T>(x: *mut T) {
	unsafe {
		let obj = x as *mut sqfs_object_t;
		((*obj).destroy.expect("SquashFS object did not provide a destroy callback"))(obj);
	}
}

fn libc_free<T>(x: *mut T) {
	unsafe { libc::free(x as *mut _ as *mut libc::c_void); }
}

fn rust_dealloc<T>(x: *mut T) {
	unsafe { std::alloc::dealloc(x as *mut u8, std::alloc::Layout::new::<T>()) }
}

fn unpack_meta_ref(meta_ref: u64) -> (u64, u64) {
	(meta_ref >> 16 & 0xffffffff, meta_ref & 0xffff)
}

fn os_to_string(s: &OsStr) -> Result<String> {
	Ok(s.to_str().ok_or_else(|| SquashfsError::OsUtf8(s.to_os_string()))?.to_string())
}

const NO_XATTRS: u32 = 0xffffffff;
const LOCK_ERR: &str = "A thread panicked while holding a lock"; // Because poisoned locks only happen when a thread panics, we probably want to panic too.
const LINK_MAX: i32 = 1000;
const BLOCK_BUF_SIZE: usize = 4096;
const PAD_TO: usize = 4096;

struct ManagedPointer<T> {
	ptr: *mut T,
	destroy: fn(*mut T),
}

impl<T> ManagedPointer<T> {
	fn null(destroy: fn(*mut T)) -> Self {
		Self { ptr: ptr::null_mut(), destroy: destroy }
	}

	fn new(ptr: *mut T, destroy: fn(*mut T)) -> Self {
		Self { ptr: ptr, destroy: destroy }
	}
	
	fn as_const(&self) -> *const T {
		self.ptr as *const T
	}
}

impl<T> std::ops::Deref for ManagedPointer<T> {
	type Target = *mut T;

	fn deref(&self) -> &Self::Target {
		&self.ptr
	}
}

impl<T> std::ops::DerefMut for ManagedPointer<T> {
	fn deref_mut(&mut self) -> &mut Self::Target {
		&mut self.ptr
	}
}

impl<T> Drop for ManagedPointer<T> {
	fn drop(&mut self) {
		(self.destroy)(**self)
	}
}

impl<T> std::fmt::Debug for ManagedPointer<T> {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		write!(f, "ManagedPointer({:?})", self.ptr)
	}
}

fn sfs_init<T>(init: &dyn Fn(*mut T) -> i32, err: &str) -> Result<T> {
	let mut ret: MaybeUninit<T> = MaybeUninit::uninit();
	sfs_check(init(ret.as_mut_ptr()), err)?;
	Ok(unsafe { ret.assume_init() })
}

fn sfs_init_ptr<T>(init: &dyn Fn(*mut *mut T) -> i32, err: &str, destroy: fn(*mut T)) -> Result<ManagedPointer<T>> {
	let mut ret: *mut T = ptr::null_mut();
	sfs_check(init(&mut ret), err)?;
	if ret.is_null() { Err(SquashfsError::LibraryReturnError(err.to_string())) }
	else { Ok(ManagedPointer::new(ret, destroy)) }
}

fn sfs_init_check_null<T>(init: &dyn Fn() -> *mut T, err: &str, destroy: fn(*mut T)) -> Result<ManagedPointer<T>> {
	let ret = init();
	if ret.is_null() { Err(SquashfsError::LibraryNullError(err.to_string())) }
	else { Ok(ManagedPointer::new(ret, destroy)) }
}
