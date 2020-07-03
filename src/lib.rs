extern crate libc;
extern crate num_derive;
extern crate num_traits;
extern crate owning_ref;

mod bindings {
	#![allow(non_camel_case_types)]
	#![allow(non_snake_case)]
	#![allow(non_upper_case_globals)]
	#![allow(dead_code)]
	include!(concat!(env!("OUT_DIR"), "/bindings.rs"));
}

use std::collections::{HashMap, HashSet};
use std::ffi::{CStr, CString, OsString};
use std::io;
use std::io::{Read, Seek};
use std::mem::MaybeUninit;
use std::path::{Path, PathBuf, Component};
use std::ptr;
use std::sync::{Arc, Mutex};
use bindings::*;
use num_derive::FromPrimitive;
use num_traits::FromPrimitive;
use owning_ref::OwningHandle;
use thiserror::Error;

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
	#[error("Couldn't read file contents from archive: {0}")] Read(#[from] std::io::Error),
	#[error("The filesystem does not support the feature: {0}")] Unsupported(String),
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

fn sfs_init<T>(init: &dyn Fn(*mut T) -> i32, err: &str) -> Result<T> {
	let mut ret: MaybeUninit<T> = MaybeUninit::uninit();
	sfs_check(init(ret.as_mut_ptr()), err)?;
	Ok(unsafe { ret.assume_init() })
}

fn sfs_init_ptr<T>(init: &dyn Fn(*mut *mut T) -> i32, err: &str) -> Result<*mut T> {
	let mut ret: *mut T = ptr::null_mut();
	sfs_check(init(&mut ret), err)?;
	if ret.is_null() { Err(SquashfsError::LibraryReturnError(err.to_string())) }
	else { Ok(ret) }
}

fn sfs_init_check_null<T>(init: &dyn Fn() -> Result<*mut T>, err: &str) -> Result<*mut T> {
	let ret = init()?;
	if ret.is_null() { Err(SquashfsError::LibraryNullError(err.to_string())) }
	else { Ok(ret) }
}

fn sfs_destroy<T>(x: *mut T) {
	unsafe {
		let obj = x as *mut sqfs_object_t;
		((*obj).destroy.expect("Squashfs object did not provide a destory callback"))(obj);
	}
}

fn libc_free<T>(x: *mut T) {
	unsafe { libc::free(x as *mut _ as *mut libc::c_void); }
}

// Canonicalize without requiring the path to actually exist in the filesystem
fn dumb_canonicalize(path: &Path) -> PathBuf {
	let mut ret = PathBuf::new();
	for part in path.components() {
		match part {
			Component::Prefix(_) => panic!("What is this, Windows?"),
			Component::CurDir => (),
			Component::RootDir => ret.clear(),
			Component::ParentDir => { ret.pop(); },
			Component::Normal(p) => ret.push(p),
		}
	}
	ret
}

fn path_to_string(path: &Path) -> Result<String> {
	Ok(path.to_str().ok_or_else(|| SquashfsError::OsUtf8(path.as_os_str().to_os_string()))?.to_string())
}

const NO_XATTRS: u32 = 0xffffffff;
const LOCK_ERR: &str = "A thread panicked while holding a lock"; // Because poisoned locks only happen when a thread panics, we probably want to panic too.
const LINK_MAX: i32 = 1000;

struct ManagedPointer<T> {
	ptr: *mut T,
	destroy: fn(*mut T),
}

impl<T> ManagedPointer<T> {
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

#[derive(Debug)]
pub struct Dir<'a> {
	node: &'a Node<'a>,
	compressor: ManagedPointer<sqfs_compressor_t>,
	reader: Mutex<ManagedPointer<sqfs_dir_reader_t>>,
}

impl<'a> Dir<'a> {
	fn new(node: &'a Node) -> Result<Self> {
		let compressor = node.container.compressor()?;
		let reader = ManagedPointer::new(sfs_init_check_null(&|| unsafe {
			Ok(sqfs_dir_reader_create(&*node.container.superblock, *compressor, *node.container.file, 0))
		}, "Couldn't create directory reader")?, sfs_destroy);
		unsafe { sfs_check(sqfs_dir_reader_open_dir(*reader, node.inode.as_const(), 0), "Couldn't open directory")?; }
		Ok(Self { node: node, compressor: compressor, reader: Mutex::new(reader) })
	}

	pub fn reset(&mut self) {
		unsafe { sqfs_dir_reader_rewind(**self.reader.lock().expect(LOCK_ERR)); }
	}

	fn read<'b>(&'b self) -> Result<Node<'a>> {
		let locked_reader = self.reader.lock().expect(LOCK_ERR);
		let entry = sfs_init_ptr(&|x| unsafe {
			sqfs_dir_reader_read(**locked_reader, x)
		}, "Couldn't read directory entries")?;
		let name_bytes = unsafe { (*entry).name.as_slice((*entry).size as usize + 1) };
		let name = String::from_utf8(name_bytes.to_vec())?;
		let node = ManagedPointer::new(sfs_init_ptr(&|x| unsafe {
			sqfs_dir_reader_get_inode(**locked_reader, x)
		}, "Couldn't read directory entry inode")?, libc_free);
		Node::new(self.node.container, node, self.node.path.as_ref().map(|path| path.join(name)))
	}

	pub fn child(&self, name: &str) -> Result<Node> {
		unsafe { sfs_check(sqfs_dir_reader_find(**self.reader.lock().expect(LOCK_ERR), CString::new(name)?.as_ptr()), &format!("Couldn't find child \"{}\"", name))? };
		self.read()
	}
}

impl<'a> std::iter::Iterator for Dir<'a> {
	type Item = Node<'a>;

	fn next(&mut self) -> Option<Self::Item> {
		self.read().ok()
	}
}

#[derive(Debug)]
pub struct File<'a> {
	node: &'a Node<'a>,
	compressor: ManagedPointer<sqfs_compressor_t>,
	reader: Mutex<ManagedPointer<sqfs_data_reader_t>>,
	offset: Mutex<u64>,
}

impl<'a> File<'a> {
	fn new(node: &'a Node) -> Result<Self> {
		let compressor = node.container.compressor()?;
		let reader = ManagedPointer::new(sfs_init_check_null(&|| unsafe {
			Ok(sqfs_data_reader_create(*node.container.file, node.container.superblock.block_size as u64, *compressor, 0))
		}, "Couldn't create data reader")?, sfs_destroy);
		unsafe { sfs_check(sqfs_data_reader_load_fragment_table(*reader, &*node.container.superblock), "Couldn't load fragment table")? };
		Ok(Self { node: node, compressor: compressor, reader: Mutex::new(reader), offset: Mutex::new(0) })
	}

	pub fn size(&self) -> u64 {
		let mut ret: u64 = 0;
		unsafe { sqfs_inode_get_file_size(self.node.inode.as_const(), &mut ret) };
		ret
	}

	pub fn to_bytes(&mut self) -> Result<Vec<u8>> {
		let mut ret = Vec::with_capacity(self.size() as usize);
		self.read_to_end(&mut ret)?;
		Ok(ret)
	}

	pub fn to_string(&mut self) -> Result<String> {
		let mut ret = String::with_capacity(self.size() as usize);
		self.read_to_string(&mut ret)?;
		Ok(ret)
	}
}

impl<'a> Read for File<'a> {
	fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
		let mut locked_offset = self.offset.lock().expect(LOCK_ERR);
		if *locked_offset >= self.size() { Ok(0) }
		else {
			let locked_reader = self.reader.lock().expect(LOCK_ERR);
			let res = unsafe { sfs_check(sqfs_data_reader_read(**locked_reader, self.node.inode.as_const(), *locked_offset, buf.as_mut_ptr() as *mut libc::c_void, buf.len() as u32), "Couldn't read file content").map_err(|e| io::Error::new(io::ErrorKind::Other, e))? };
			*locked_offset += res as u64;
			Ok(res as usize)
		}
	}
}

impl<'a> Seek for File<'a> {
	fn seek(&mut self, pos: io::SeekFrom) -> io::Result<u64> {
		let mut locked_offset = self.offset.lock().expect(LOCK_ERR);
		let newoff = match pos {
			io::SeekFrom::Start(off) => off as i64,
			io::SeekFrom::End(off) => self.size() as i64 + off,
			io::SeekFrom::Current(off) => *locked_offset as i64 + off,
		};
		if newoff < 0 {
			Err(io::Error::new(io::ErrorKind::Other, "Attempted to seek before beginning of file"))
		}
		else {
			*locked_offset = newoff as u64;
			Ok(*locked_offset)
		}
	}
}

#[derive(Debug)]
pub enum Data<'a> {
	File(File<'a>),
	Dir(Dir<'a>),
	Symlink(String),
	BlockDev(u32, u32),
	CharDev(u32, u32),
	Fifo,
	Socket,
}

impl<'a> Data<'a> {
	fn new(node: &'a Node) -> Result<Self> {
		unsafe fn arr_to_string<'a, T>(arr: &bindings::__IncompleteArrayField<T>, len: usize) -> String {
			let slice = std::slice::from_raw_parts(arr.as_ptr() as *const u8, len);
			String::from_utf8_lossy(slice).into_owned()
		}
		fn get_dev_nums(dev: u32) -> (u32, u32) {
			((dev & 0xfff00) >> 8, (dev & 0xff) | ((dev >> 12) & 0xfff00))
		}
		match unsafe { (***node.inode).base.type_ } as u32 {
			SQFS_INODE_TYPE_SQFS_INODE_DIR | SQFS_INODE_TYPE_SQFS_INODE_EXT_DIR => Ok(Self::Dir(Dir::new(node)?)),
			SQFS_INODE_TYPE_SQFS_INODE_FILE | SQFS_INODE_TYPE_SQFS_INODE_EXT_FILE => Ok(Self::File(File::new(node)?)),
			SQFS_INODE_TYPE_SQFS_INODE_SLINK => Ok(unsafe {
				Self::Symlink(arr_to_string(&(***node.inode).extra, (***node.inode).data.slink.target_size as usize))
			}),
			SQFS_INODE_TYPE_SQFS_INODE_EXT_SLINK => Ok(unsafe {
				Self::Symlink(arr_to_string(&(***node.inode).extra, (***node.inode).data.slink_ext.target_size as usize))
			}),
			SQFS_INODE_TYPE_SQFS_INODE_BDEV => Ok(unsafe {
				let (maj, min) = get_dev_nums((***node.inode).data.dev.devno);
				Self::BlockDev(maj, min)
			}),
			SQFS_INODE_TYPE_SQFS_INODE_EXT_BDEV => Ok(unsafe {
				let (maj, min) = get_dev_nums((***node.inode).data.dev.devno);
				Self::BlockDev(maj, min)
			}),
			SQFS_INODE_TYPE_SQFS_INODE_CDEV => Ok(unsafe {
				let (maj, min) = get_dev_nums((***node.inode).data.dev.devno);
				Self::CharDev(maj, min)
			}),
			SQFS_INODE_TYPE_SQFS_INODE_EXT_CDEV => Ok(unsafe {
				let (maj, min) = get_dev_nums((***node.inode).data.dev.devno);
				Self::CharDev(maj, min)
			}),
			SQFS_INODE_TYPE_SQFS_INODE_FIFO | SQFS_INODE_TYPE_SQFS_INODE_EXT_FIFO  => Ok(Self::Fifo),
			SQFS_INODE_TYPE_SQFS_INODE_SOCKET | SQFS_INODE_TYPE_SQFS_INODE_EXT_SOCKET  => Ok(Self::Socket),
			_ => Err(SquashfsError::LibraryReturnError("Unsupported inode type".to_string())),
		}
	}
	
	fn name(&self) -> String {
		match self {
			Data::File(_) => "regular file",
			Data::Dir(_) => "directory",
			Data::Symlink(_) => "symbolic link",
			Data::BlockDev(_, _) => "block device",
			Data::CharDev(_, _) => "character device",
			Data::Fifo => "named pipe",
			Data::Socket => "socket",
		}.to_string()
	}
}

#[repr(u32)]
#[derive(Clone, Copy)]
pub enum XattrType {
	User = SQFS_XATTR_TYPE_SQFS_XATTR_USER,
	Trusted = SQFS_XATTR_TYPE_SQFS_XATTR_TRUSTED,
	Security = SQFS_XATTR_TYPE_SQFS_XATTR_SECURITY,
}

pub struct OwnedFile<'a> {
	handle: OwningHandle<Box<Node<'a>>, Box<File<'a>>>,
}

impl<'a> Read for OwnedFile<'a> {
	fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
		(*self.handle).read(buf)
	}
}

impl<'a> Seek for OwnedFile<'a> {
	fn seek(&mut self, pos: io::SeekFrom) -> io::Result<u64> {
		(*self.handle).seek(pos)
	}
}

impl<'a> std::ops::Deref for OwnedFile<'a> {
	type Target = File<'a>;

	fn deref(&self) -> &Self::Target {
		self.handle.deref()
	}
}

impl<'a> std::ops::DerefMut for OwnedFile<'a> {
	fn deref_mut(&mut self) -> &mut Self::Target {
		self.handle.deref_mut()
	}
}

pub struct OwnedDir<'a> {
	handle: OwningHandle<Box<Node<'a>>, Box<Dir<'a>>>,
}

impl<'a> std::iter::Iterator for OwnedDir<'a> {
	type Item = Node<'a>;

	fn next(&mut self) -> Option<Self::Item> {
		(*self.handle).next()
	}
}

impl<'a> std::ops::Deref for OwnedDir<'a> {
	type Target = Dir<'a>;

	fn deref(&self) -> &Self::Target {
		self.handle.deref()
	}
}

impl<'a> std::ops::DerefMut for OwnedDir<'a> {
	fn deref_mut(&mut self) -> &mut Self::Target {
		self.handle.deref_mut()
	}
}

pub struct Node<'a> {
	container: &'a Archive,
	path: Option<PathBuf>,
	inode: Arc<ManagedPointer<sqfs_inode_generic_t>>,
}

impl<'a> Node<'a> {
	fn new(container: &'a Archive, inode: ManagedPointer<sqfs_inode_generic_t>, path: Option<PathBuf>) -> Result<Self> {
		Ok(Self { container: container, path: path, inode: Arc::new(inode) })
	}

	pub fn xattrs(&self, category: XattrType) -> Result<HashMap<Vec<u8>, Vec<u8>>> {
		if self.container.superblock.flags & SQFS_SUPER_FLAGS_SQFS_FLAG_NO_XATTRS as u16 != 0 { Ok(HashMap::new()) }
		else {
			let compressor = self.container.compressor()?;
			let xattr_reader = unsafe {
				let ret = ManagedPointer::new(sqfs_xattr_reader_create(0), sfs_destroy);
				sfs_check(sqfs_xattr_reader_load(*ret, &*self.container.superblock, *self.container.file, *compressor), "Couldn't create xattr reader")?;
				ret
			};
			let mut xattr_idx: u32 = NO_XATTRS;
			unsafe { sfs_check(sqfs_inode_get_xattr_index(self.inode.as_const(), &mut xattr_idx), "Couldn't get xattr index")? };
			let desc = sfs_init(&|x| unsafe {
				sqfs_xattr_reader_get_desc(*xattr_reader, xattr_idx, x)
			}, "Couldn't get xattr descriptor")?;
			let mut ret: HashMap<Vec<u8>, Vec<u8>> = HashMap::new();
			unsafe { sfs_check(sqfs_xattr_reader_seek_kv(*xattr_reader, &desc), "Couldn't seek to xattr location")? };
			for _ in 0..desc.count {
				let prefixlen = unsafe { CStr::from_ptr(sqfs_get_xattr_prefix(category as u32)).to_bytes().len() };
				let key = ManagedPointer::new(sfs_init_ptr(&|x| unsafe {
					sqfs_xattr_reader_read_key(*xattr_reader, x)
				}, "Couldn't read xattr key")?, libc_free);
				if unsafe { (**key).type_ } as u32 & SQFS_XATTR_TYPE_SQFS_XATTR_FLAG_OOL != 0 {
					unimplemented!()
				}
				let val = ManagedPointer::new(sfs_init_ptr(&|x| unsafe {
					sqfs_xattr_reader_read_value(*xattr_reader, *key, x)
				}, "Couldn't read xattr value")?, libc_free);
				if unsafe { (**key).type_ } as u32 & SQFS_XATTR_TYPE_SQFS_XATTR_PREFIX_MASK == category as u32 {
					unsafe {
						let keyvec = (**key).key.as_slice((**key).size as usize + prefixlen)[prefixlen..].to_vec();
						let valvec = (**val).value.as_slice((**val).size as usize).to_vec();
						ret.insert(keyvec, valvec);
					}
				}
			}
			Ok(ret)
		}
	}

	pub fn id(&self) -> u32 {
		unsafe { (***self.inode).base.inode_number }
	}

	pub fn data(&self) -> Result<Data> {
		Data::new(&self)
	}

	pub fn path(&self) -> Option<&Path> {
		self.path.as_ref().map(|path| path.as_path())
	}
	
	fn path_string(&self) -> String {
		match &self.path {
			Some(path) => path.display().to_string(), //path_to_string(&path),
			None => "<unknown>".to_string(),
		}
	}

	pub fn name(&self) -> Option<String> {
		self.path.as_ref().map(|path| path.file_name().map(|x| x.to_string_lossy().to_string()).unwrap_or("/".to_string()))
	}

	pub fn parent(&self) -> Result<Self> {
		self.path.as_ref().map(|path| {
			let ppath = path.parent().unwrap_or(&Path::new(""));
			self.container.get(&path_to_string(ppath)?)
		}).ok_or(SquashfsError::NoPath)?
	}

	pub fn resolve(&self) -> Result<Self> {
		let mut visited = HashSet::new();
		let mut cur = Box::new(self.clone());
		let mut i = 0;
		loop {
			match cur.data()? {
				Data::Symlink(targetstr) => {
					let rawtarget = PathBuf::from(targetstr);
					let target = match cur.path {
						Some(path) => path.parent().unwrap_or(&Path::new("")).join(rawtarget),
						None => match rawtarget.is_absolute() {
							true => rawtarget,
							false => Err(SquashfsError::NoPath)?,
						}
					};
					if !visited.insert(target.clone()) {
						return Err(SquashfsError::LinkLoop(target));
					}
					cur = Box::new(cur.container.get_path(&target)?);
				}
				_ => return Ok(*cur),
			}
			i += 1;
			if i > LINK_MAX { Err(SquashfsError::LinkChain(LINK_MAX))?; }
		}
	}

	pub fn as_file(&self) -> Result<File> {
		match self.data()? {
			Data::File(f) => Ok(f),
			other => Err(SquashfsError::WrongType(self.path_string(), other.name(), "regular file".to_string())),
		}
	}

	pub fn into_owned_file(self) -> Result<OwnedFile<'a>> {
		Ok(OwnedFile { handle: OwningHandle::try_new(Box::new(self), |x| unsafe { (*x).as_file().map(|x| Box::new(x)) })? })
	}

	pub fn as_dir(&self) -> Result<Dir> {
		match self.data()? {
			Data::Dir(d) => Ok(d),
			other => Err(SquashfsError::WrongType(self.path_string(), other.name(), "directory".to_string())),
		}
	}

	pub fn into_owned_dir(self) -> Result<OwnedDir<'a>> {
		Ok(OwnedDir { handle: OwningHandle::try_new(Box::new(self), |x| unsafe { (*x).as_dir().map(|x| Box::new(x)) })? })
	}
}

impl<'a> std::clone::Clone for Node<'a> {
	fn clone(&self) -> Self {
		Self { container: self.container, path: self.path.clone(), inode: self.inode.clone() }
	}
}

impl<'a> std::fmt::Display for Node<'a> {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		write!(f, "{} at {}", self.data().map(|x| x.name()).unwrap_or("inaccessible file".to_string()), self.path_string())
	}
}

impl<'a> std::fmt::Debug for Node<'a> {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		write!(f, "Node({:?})", self.path)
	}
}

pub struct Archive {
	file: ManagedPointer<sqfs_file_t>,
	superblock: Box<sqfs_super_t>,
	compressor_config: Box<sqfs_compressor_config_t>,
}

impl Archive {
	pub fn new(path: &Path) -> Result<Self> {
		let cpath = CString::new(path_to_string(&path)?)?;
		let file = ManagedPointer::new(sfs_init_check_null(&|| unsafe {
			Ok(sqfs_open_file(cpath.as_ptr(), SQFS_FILE_OPEN_FLAGS_SQFS_FILE_OPEN_READ_ONLY))
		}, &format!("Couldn't open input file {}", path.display()))?, sfs_destroy);
		let superblock = Box::new(sfs_init(&|x| unsafe {
			sqfs_super_read(x, *file)
		}, "Couldn't read archive superblock")?);
		let compressor_config = Box::new(sfs_init(&|x| unsafe {
			sqfs_compressor_config_init(x, superblock.compression_id as u32, superblock.block_size as u64, SQFS_COMP_FLAG_SQFS_COMP_FLAG_UNCOMPRESS as u16)
		}, "Couldn't read archive compressor config")?);
		Ok(Self { file: file, superblock: superblock, compressor_config: compressor_config })
	}

	fn compressor(&self) -> Result<ManagedPointer<sqfs_compressor_t>> {
		Ok(ManagedPointer::new(sfs_init_ptr(&|x| unsafe {
			sqfs_compressor_create(&*self.compressor_config, x)
		}, "Couldn't create compressor")?, sfs_destroy))
	}

	pub fn size(&self) -> u32 {
		self.superblock.inode_count
	}

	pub fn get_path(&self, path: &Path) -> Result<Node> {
		let compressor = self.compressor()?;
		let dir_reader = ManagedPointer::new(sfs_init_check_null(&|| unsafe {
			Ok(sqfs_dir_reader_create(&*self.superblock, *compressor, *self.file, 0))
		}, "Couldn't create directory reader")?, sfs_destroy);
		let root = ManagedPointer::new(sfs_init_ptr(&|x| unsafe {
			sqfs_dir_reader_get_root_inode(*dir_reader, x)
		}, "Couldn't get filesystem root")?, libc_free);
		let pathbuf = dumb_canonicalize(path);
		if &pathbuf == Path::new("/") {
			Node::new(&self, root, Some(pathbuf))
		}
		else {
			let cpath = CString::new(path_to_string(&pathbuf)?)?;
			let inode = ManagedPointer::new(sfs_init_ptr(&|x| unsafe {
				sqfs_dir_reader_find_by_path(*dir_reader, *root, cpath.as_ptr(), x)
			}, &format!("Unable to access path {}", path.display()))?, libc_free);
			Node::new(&self, inode, Some(pathbuf))
		}
	}

	pub fn get_id(&self, id: u64) -> Result<Node> {
		if self.superblock.flags & SQFS_SUPER_FLAGS_SQFS_FLAG_EXPORTABLE as u16 == 0 { Err(SquashfsError::Unsupported("inode indexing".to_string()))?; }
		if id <= 0 || id > self.superblock.inode_count as u64 { Err(SquashfsError::Range(id, self.superblock.inode_count as u64))? }
		let compressor = self.compressor()?;
		let export_reader = ManagedPointer::new(sfs_init_check_null(&|| unsafe {
			Ok(sqfs_meta_reader_create(*self.file, *compressor, 0, self.superblock.bytes_used)) // It would be nice to be able to set reasonable limits here.
		}, "Couldn't create export table reader")?, sfs_destroy);
		let (block, offset) = ((id - 1) * 8 / self.superblock.block_size as u64, (id - 1) * 8 % self.superblock.block_size as u64);
		let block_start: u64 = sfs_init(&|x| unsafe {
			let read_at = (**self.file).read_at.expect("File object does not implement read_at");
			read_at(*self.file, self.superblock.export_table_start + block, x as *mut libc::c_void, 8)
		}, "Couldn't read inode table")?;

		let mut noderef: u64 = 0;
		unsafe {
			sfs_check(sqfs_meta_reader_seek(*export_reader, block_start, offset), "Couldn't seek to inode reference")?;
			sfs_check(sqfs_meta_reader_read(*export_reader, &mut noderef as *mut u64 as *mut libc::c_void, 8), "Couldn't read inode reference")?;
		}
		let (block, offset) = (noderef >> 16 & 0xffffffff, noderef & 0xffff);
		let inode = ManagedPointer::new(sfs_init_ptr(&|x| unsafe {
			sqfs_meta_reader_read_inode(*export_reader, &*self.superblock, block as u64, offset as u64, x)
		}, "Couldn't read inode")?, libc_free);
		Node::new(&self, inode, None)
	}

	pub fn get(&self, path: &str) -> Result<Node> {
		self.get_path(Path::new(path))
	}
}

unsafe impl Send for Archive { }
unsafe impl Sync for Archive { }
