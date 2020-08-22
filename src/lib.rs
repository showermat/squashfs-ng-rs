#[macro_use] extern crate lazy_static;
extern crate libc;
extern crate mmap;
extern crate num_derive;
extern crate num_traits;
extern crate owning_ref;
extern crate walkdir;
extern crate xattr;

use std::mem::MaybeUninit;
use std::ffi::{OsStr, OsString};
use std::path::PathBuf;
use std::ptr;
use bindings::*;
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

pub mod read;
pub mod write;

type BoxedError = Box<dyn std::error::Error + std::marker::Send + std::marker::Sync>;

#[derive(Error, Debug, FromPrimitive)]
#[repr(i32)]
pub enum LibError {
	#[error("Failed to allocate memory")] Alloc = -1,
	#[error("Generic I/O failure occurred")] Io = -2,
	#[error("Compressor failed to extract data")] Compressor = -3,
	#[error("Internal error occurred")] Internal = -4,
	#[error("Archive file appears to be corrupted")] Corrupted = -5,
	#[error("Unsupported feature used")] Unsupported = -6,
	#[error("Archive would overflow memory")] Overflow = -7,
	#[error("Out-of-bounds access attempted")] OutOfBounds = -8,
	#[error("Superblock magic number incorrect")] SuperMagic = -9,
	#[error("Unsupported archive version")] SuperVersion = -10,
	#[error("Archive block size is invalid")] SuperBlockSize = -11,
	#[error("Not a directory")] NotDir = -12,
	#[error("Path does not exist")] NoEntry = -13,
	#[error("Hard link loop detected")] LinkLoop = -14,
	#[error("Not a regular file")] NotFile = -15,
	#[error("Invalid argument passed")] ArgInvalid = -16,
	#[error("Library operations performed in incorrect order")] Sequence = -17,
}

#[derive(Error, Debug)]
pub enum SquashfsError {
	#[error("Input contains an invalid null character")] NullInput(#[from] std::ffi::NulError),
	#[error("Encoded string is not valid UTF-8")] Utf8(#[from] std::string::FromUtf8Error),
	#[error("OS string is not valid UTF-8")] OsUtf8(OsString),
	#[error("{0}: {1}")] LibraryError(String, LibError),
	#[error("{0}: Unknown error {1} in Squashfs library")] UnknownLibraryError(String, i32),
	#[error("{0}: Squashfs library did not return expected value")] LibraryReturnError(String),
	#[error("{0}")] LibraryNullError(String),
	#[error("Symbolic link chain exceeds {0} elements")] LinkChain(i32), // Can I use a const in the formatting string?
	#[error("Symbolic link loop detected containing {0}")] LinkLoop(PathBuf),
	#[error("{0} is type {1}, not {2}")] WrongType(String, String, String),
	#[error("Tried to copy an object that can't be copied")] Copy,
	#[error("Tried to get parent of a node with an unknown path")] NoPath,
	#[error("Inode index {0} is not within limits 1..{1}")] Range(u64, u64),
	#[error("Couldn't read file: {0}")] Read(#[from] std::io::Error),
	#[error("The filesystem does not support the feature: {0}")] Unsupported(String),
	#[error("Memory mapping failed: {0}")] Mmap(#[from] mmap::MapError),
	#[error("Couldn't get the current system time: {0}")] Time(#[from] std::time::SystemTimeError),
	#[error("Refusing to create empty archive")] Empty,
	#[error("Tried to write directory {0} before child {1}")] WriteOrder(u32, u32),
	#[error("Tried to write unknown or unsupported file type")] WriteType(std::fs::FileType),
	#[error("Callback returned an error")] WrappedError(BoxedError),
}

type Result<T> = std::result::Result<T, SquashfsError>;

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
		((*obj).destroy.expect("Squashfs object did not provide a destroy callback"))(obj);
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
