#![allow(dead_code)] // FIXME

extern crate libc;
extern crate num_derive;
extern crate num_traits;

mod bindings {
	#![allow(non_camel_case_types)]
	#![allow(non_snake_case)]
	#![allow(non_upper_case_globals)]
	include!(concat!(env!("OUT_DIR"), "/bindings.rs"));
}

use std::collections::{HashMap, HashSet};
use std::ffi::{CStr, CString, OsString};
use std::io;
use std::io::{Read, Seek};
use std::mem::MaybeUninit;
use std::path::{Path, PathBuf, Component};
use std::ptr;
use bindings::*;
use num_derive::FromPrimitive;
use num_traits::FromPrimitive;
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
	#[error("Symbolic link loop detected containing {0}")] LinkLoop(PathBuf),
	#[error("{0} is type {1}, not {2}")] WrongType(PathBuf, String, String),
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

fn sfs_init_check_null<T>(init: &dyn Fn() -> *mut T, err: &str) -> Result<*mut T> {
	let ret = init();
	if ret.is_null() { Err(SquashfsError::LibraryNullError(err.to_string())) }
	else { Ok(ret) }
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

#[derive(Debug)]
pub struct Dir<'a> {
	node: &'a Node<'a>,
	reader: *mut sqfs_dir_reader_t,
}

impl<'a> Dir<'a> {
	fn new(node: &'a Node) -> Result<Self> {
		let reader = sfs_init_check_null(&|| unsafe {
			sqfs_dir_reader_create(&*node.container.superblock, node.container.compressor, node.container.file, 0)
		}, "Couldn't create directory reader")?;
		unsafe {
			sfs_check(sqfs_dir_reader_open_dir(reader, node.inode, 0), "Couldn't open directory")?;
		}
		Ok(Self { node: node, reader: reader })
	}

	pub fn reset(&mut self) {
		unsafe { sqfs_dir_reader_rewind(self.reader); }
	}

	fn read(&self) -> Result<Node> {
		let entry = sfs_init_ptr(&|x| unsafe {
			sqfs_dir_reader_read(self.reader, x)
		}, "Couldn't read directory entries")?;
		let name_bytes = unsafe { (*entry).name.as_slice((*entry).size as usize + 1) };
		let name = String::from_utf8(name_bytes.to_vec())?;
		let node = sfs_init_ptr(&|x| unsafe {
			sqfs_dir_reader_get_inode(self.reader, x)
		}, "Couldn't read directory entry inode")?;
		Node::new(self.node.container, node, self.node.path.join(name))
	}

	pub fn child(&self, name: &str) -> Result<Node> {
		unsafe { sfs_check(sqfs_dir_reader_find(self.reader, CString::new(name)?.as_ptr()), &format!("Couldn't find child \"{}\"", name))? };
		self.read()
	}

	pub fn node(&self) -> &'a Node {
		self.node
	}
}

impl<'a> std::iter::Iterator for Dir<'a> {
	type Item = Node<'a>;

	fn next(&mut self) -> Option<Self::Item> {
		// TODO Figure out lifetime issue preventing this from just being self.read().ok()
		match self.read() {
			Err(_) => None,
			Ok(node) => Node::new(self.node.container, node.inode, node.path.clone()).ok(),
		}
	}
}

#[derive(Debug)]
pub struct File<'a> {
	node: &'a Node<'a>,
	reader: *mut sqfs_data_reader_t,
	offset: u64,
}

impl<'a> File<'a> {
	fn new(node: &'a Node) -> Result<Self> {
		let reader = sfs_init_check_null(&|| unsafe {
			sqfs_data_reader_create(node.container.file, node.container.superblock.block_size as u64, node.container.compressor, 0)
		}, "Couldn't create data reader")?;
		unsafe { sfs_check(sqfs_data_reader_load_fragment_table(reader, &*node.container.superblock), "Couldn't load fragment table")? };
		Ok(Self { node: node, reader: reader, offset: 0 })
	}

	pub fn size(&self) -> u64 {
		let mut ret: u64 = 0;
		unsafe { sqfs_inode_get_file_size(self.node.inode, &mut ret) };
		ret
	}

	pub fn node(&self) -> &'a Node {
		self.node
	}
}

impl<'a> Read for File<'a> {
	fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
		if self.offset >= self.size() { Ok(0) }
		else {
			let res = unsafe { sfs_check(sqfs_data_reader_read(self.reader, self.node.inode, self.offset, buf.as_mut_ptr() as *mut libc::c_void, buf.len() as u32), "Couldn't read file content").map_err(|e| io::Error::new(io::ErrorKind::Other, e))? };
			self.offset += res as u64;
			Ok(res as usize)
		}
	}
}

impl<'a> Seek for File<'a> {
	fn seek(&mut self, pos: io::SeekFrom) -> io::Result<u64> {
		let newoff = match pos {
			io::SeekFrom::Start(off) => off as i64,
			io::SeekFrom::End(off) => self.size() as i64 + off,
			io::SeekFrom::Current(off) => self.offset as i64 + off,
		};
		if newoff < 0 {
			Err(io::Error::new(io::ErrorKind::Other, "Attempted to seek before beginning of file"))
		}
		else {
			self.offset = newoff as u64;
			Ok(self.offset)
		}
	}
}

#[derive(Debug)]
pub enum Data<'a> {
	File(File<'a>),
	Dir(Dir<'a>),
	Symlink(String),
	BlockDev(u32),
	CharDev(u32),
	Fifo,
	Socket,
}

impl<'a> Data<'a> {
	fn new(node: &'a Node) -> Result<Self> {
		unsafe fn arr_to_string<'a, T>(arr: &bindings::__IncompleteArrayField<T>, len: usize) -> String {
			let slice = std::slice::from_raw_parts(arr.as_ptr() as *const u8, len);
			String::from_utf8_lossy(slice).into_owned()
		}
		match unsafe { (*node.inode).base.type_ } as u32 {
			SQFS_INODE_TYPE_SQFS_INODE_DIR | SQFS_INODE_TYPE_SQFS_INODE_EXT_DIR => Ok(Self::Dir(Dir::new(node)?)),
			SQFS_INODE_TYPE_SQFS_INODE_FILE | SQFS_INODE_TYPE_SQFS_INODE_EXT_FILE => Ok(Self::File(File::new(node)?)),
			SQFS_INODE_TYPE_SQFS_INODE_SLINK => Ok(unsafe {
				Self::Symlink(arr_to_string(&(*node.inode).extra, (*node.inode).data.slink.target_size as usize))
			}),
			SQFS_INODE_TYPE_SQFS_INODE_EXT_SLINK => Ok(unsafe {
				Self::Symlink(arr_to_string(&(*node.inode).extra, (*node.inode).data.slink_ext.target_size as usize))
			}),
			SQFS_INODE_TYPE_SQFS_INODE_BDEV => Ok(unsafe {
				Self::BlockDev((*node.inode).data.dev.devno)
			}),
			SQFS_INODE_TYPE_SQFS_INODE_EXT_BDEV => Ok(unsafe {
				Self::BlockDev((*node.inode).data.dev_ext.devno)
			}),
			SQFS_INODE_TYPE_SQFS_INODE_CDEV => Ok(unsafe {
				Self::CharDev((*node.inode).data.dev.devno)
			}),
			SQFS_INODE_TYPE_SQFS_INODE_EXT_CDEV => Ok(unsafe {
				Self::CharDev((*node.inode).data.dev_ext.devno)
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
			Data::BlockDev(_) => "block device",
			Data::CharDev(_) => "character device",
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

// TODO See how many of these instance variables (in all classes) we can make *const rather than *mut
// TODO Also check what should be clonable and whether that might share state unsafely
pub struct Node<'a> {
	container: &'a Archive,
	path: PathBuf,
	inode: *const sqfs_inode_generic_t,
}

impl<'a> Node<'a> {
	fn new(container: &'a Archive, inode: *const sqfs_inode_generic_t, path: PathBuf) -> Result<Self> {
		Ok(Self { container: container, path: path, inode: inode })
	}

	pub fn xattrs(&self, category: XattrType) -> Result<HashMap<Vec<u8>, Vec<u8>>> {
		let xattr_reader = self.container.xattr_reader()?;
		let mut xattr_idx: u32 = NO_XATTRS;
		unsafe { sfs_check(sqfs_inode_get_xattr_index(self.inode, &mut xattr_idx), "Couldn't get xattr index")? };
		let desc = sfs_init(&|x| unsafe {
			sqfs_xattr_reader_get_desc(xattr_reader, xattr_idx, x)
		}, "Couldn't get xattr descriptor")?;
		let mut ret: HashMap<Vec<u8>, Vec<u8>> = HashMap::new();
		unsafe { sfs_check(sqfs_xattr_reader_seek_kv(xattr_reader, &desc), "Couldn't seek to xattr location")? };
		for _ in 0..desc.count {
			let prefixlen = unsafe { CStr::from_ptr(sqfs_get_xattr_prefix(category as u32)).to_bytes().len() };
			let key = sfs_init_ptr(&|x| unsafe {
				sqfs_xattr_reader_read_key(xattr_reader, x)
			}, "Couldn't read xattr key")?;
			if unsafe { (*key).type_ } as u32 & SQFS_XATTR_TYPE_SQFS_XATTR_FLAG_OOL != 0 {
				unimplemented!()
			}
			let val = sfs_init_ptr(&|x| unsafe {
				sqfs_xattr_reader_read_value(xattr_reader, key, x)
			}, "Couldn't read xattr value")?;
			if unsafe { (*key).type_ } as u32 & SQFS_XATTR_TYPE_SQFS_XATTR_PREFIX_MASK == category as u32 {
				unsafe {
					let keyvec = (*key).key.as_slice((*key).size as usize + prefixlen)[prefixlen..].to_vec();
					let valvec = (*val).value.as_slice((*val).size as usize).to_vec();
					ret.insert(keyvec, valvec);
				}
			}
			unsafe {
				libc::free(val as *mut libc::c_void);
				libc::free(key as *mut libc::c_void);
			}
		}
		// FIXME Ensure this happens even in the case of an early return
		unsafe { sfs_destroy(xattr_reader as *mut sqfs_object_t); }
		Ok(ret)
	}

	pub fn data(&self) -> Result<Data> {
		Data::new(&self)
	}

	pub fn path(&self) -> &Path {
		&self.path
	}

	pub fn name(&self) -> String {
		self.path.file_name().map(|x| x.to_string_lossy().to_string()).unwrap_or("/".to_string())
	}

	pub fn parent(&self) -> Result<Self> {
		let ppath = self.path.parent().unwrap_or(&Path::new(""));
		self.container.get(&path_to_string(ppath)?)
	}

	pub fn resolve(&self) -> Result<Self> {
		// TODO Error out if the link chain is more than 1000 elements
		let mut visited = HashSet::new();
		let mut cur = Box::new(self.clone());
		loop {
			match cur.data()? {
				Data::Symlink(targetstr) => {
					let target = cur.path.parent().unwrap_or(&Path::new("")).join(targetstr);
					if !visited.insert(target.clone()) {
						return Err(SquashfsError::LinkLoop(target));
					}
					cur = Box::new(cur.container.getpath(&target)?);
				}
				_ => return Ok(*cur),
			}
		}
	}

	pub fn as_file(&self) -> Result<File> {
		match self.data()? {
			Data::File(f) => Ok(f),
			other => Err(SquashfsError::WrongType(self.path.to_path_buf(), other.name(), "regular file".to_string())),
		}
	}

	pub fn as_dir(&self) -> Result<Dir> {
		match self.data()? {
			Data::Dir(d) => Ok(d),
			other => Err(SquashfsError::WrongType(self.path.to_path_buf(), other.name(), "directory".to_string())),
		}
	}
}

impl<'a> std::clone::Clone for Node<'a> {
	fn clone(&self) -> Self {
		Self { container: self.container, path: self.path.clone(), inode: self.inode }
	}
}

impl<'a> std::fmt::Display for Node<'a> {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		write!(f, "{} at {}", self.data().unwrap(/*TODO*/).name(), self.path.display())
	}
}

impl<'a> std::fmt::Debug for Node<'a> {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		write!(f, "node")
	}
}

pub struct Archive {
	file: *mut sqfs_file_t,
	superblock: Box<sqfs_super_t>,
	compressor_config: Box<sqfs_compressor_config_t>,
	compressor: *mut sqfs_compressor_t,
	dir_reader: *mut sqfs_dir_reader_t,
	root: *mut sqfs_inode_generic_t,
}

impl Archive {
	pub fn new(path: &str) -> Result<Self> {
		let cpath = CString::new(path)?;
		// FIXME If something errors halfway through initialization, we'll leak memory
		let file = sfs_init_check_null(&|| unsafe {
			sqfs_open_file(cpath.as_ptr(), SQFS_FILE_OPEN_FLAGS_SQFS_FILE_OPEN_READ_ONLY)
		}, &format!("Couldn't open input file {}", path))?;
		let superblock = Box::new(sfs_init(&|x| unsafe {
			sqfs_super_read(x, file)
		}, "Couldn't read archive superblock")?);
		let compressor_config = Box::new(sfs_init(&|x| unsafe {
			sqfs_compressor_config_init(x, superblock.compression_id as u32, superblock.block_size as u64, SQFS_COMP_FLAG_SQFS_COMP_FLAG_UNCOMPRESS as u16)
		}, "Couldn't read archive compressor config")?);
		let compressor = sfs_init_ptr(&|x| unsafe {
			sqfs_compressor_create(&*compressor_config, x)
		}, "Couldn't create compressor")?;
		let dir_reader = sfs_init_check_null(&|| unsafe {
			sqfs_dir_reader_create(&*superblock, compressor, file, 0)
		}, "Couldn't create directory reader")?;
		let root = sfs_init_ptr(&|x| unsafe {
			sqfs_dir_reader_get_root_inode(dir_reader, x)
		}, "Couldn't get filesystem root")?;
		Ok(Self { file: file, superblock: superblock, compressor_config: compressor_config, compressor: compressor, dir_reader: dir_reader, root: root })
	}

	fn xattr_reader(&self) -> Result<*mut sqfs_xattr_reader_t> {
		unsafe {
			let ret = sqfs_xattr_reader_create(0);
			sfs_check(sqfs_xattr_reader_load(ret, &*self.superblock, self.file, self.compressor), "Couldn't create xattr reader")?;
			Ok(ret)
		}
	}


	fn getpath(&self, path: &Path) -> Result<Node> {
		let pathbuf = dumb_canonicalize(path);
		if &pathbuf == Path::new("/") { Node::new(&self, self.root, pathbuf) }
		else {
			let cpath = CString::new(path_to_string(&pathbuf)?)?;
			let inode = sfs_init_ptr(&|x| unsafe {
				sqfs_dir_reader_find_by_path(self.dir_reader, self.root, cpath.as_ptr(), x)
			}, &format!("Unable to access path {}", path.display()))?;
			Node::new(&self, inode, pathbuf)
		}
	}

	pub fn get(&self, path: &str) -> Result<Node> {
		self.getpath(Path::new(path))
	}
}

impl Drop for Archive {
	fn drop(&mut self) {
		unsafe {
			sfs_destroy(self.compressor as *mut sqfs_object_t);
			sfs_destroy(self.file as *mut sqfs_object_t);
		}
	}
}

unsafe fn sfs_destroy(obj: *mut sqfs_object_t) {
	((*obj).destroy.expect("Squashfs object did not provide a destory callback"))(obj);
}

fn oldtest() -> Result<()> {
	fn sfs_err(desc: &str) -> Result<()> {
		Err(SquashfsError::LibraryReturnError(desc.to_string()))
	}
	let fname = "/home/matt/Scratch/wikivoyage.sfs";
	unsafe {
		let file = sqfs_open_file(CString::new(fname)?.as_ptr(), SQFS_FILE_OPEN_FLAGS_SQFS_FILE_OPEN_READ_ONLY);
		if file.is_null() { sfs_err("Couldn't open input file")?; }
		let superblock = sfs_init(&|x| sqfs_super_read(x, file), "Couldn't read archive superblock")?;
		let compressor_config = sfs_init(&|x| sqfs_compressor_config_init(x, superblock.compression_id as u32, superblock.block_size as u64, SQFS_COMP_FLAG_SQFS_COMP_FLAG_UNCOMPRESS as u16), "Couldn't read archive compressor config")?;
		let compressor = sfs_init_ptr(&|x| sqfs_compressor_create(&compressor_config, x), "Couldn't create compressor")?;
		let dir_reader = sqfs_dir_reader_create(&superblock, compressor, file, 0);
		if dir_reader.is_null() { sfs_err("Couldn't create directory reader")?; }
		let root = {
			let mut ret: *mut sqfs_inode_generic_t = ptr::null_mut();
			sfs_check(sqfs_dir_reader_get_root_inode(dir_reader, &mut ret), "Couldn't get root inode")?;
			if ret.is_null() { sfs_err("Couldn't get root inode")?; }
			ret
		};
		sfs_check(sqfs_dir_reader_open_dir(dir_reader, root, 0), "Couldn't open directory")?;
		let mut dir_entry: *mut sqfs_dir_entry_t = ptr::null_mut();
		loop {
			if sfs_check(sqfs_dir_reader_read(dir_reader, &mut dir_entry), "Couldn't read directory")? > 0 { break; }
			if dir_entry.is_null() { sfs_err("Couldn't read directory")?; }
			let name_bytes = (*dir_entry).name.as_slice((*dir_entry).size as usize + 1);
			let name = String::from_utf8_lossy(name_bytes).into_owned();
			println!("{}", name);
		}
		let inode = {
			let mut ret: *mut sqfs_inode_generic_t = ptr::null_mut();
			sfs_check(sqfs_dir_reader_find_by_path(dir_reader, root, CString::new("_meta/info.lua")?.as_ptr(), &mut ret), "Couldn't find path")?;
			if ret.is_null() { sfs_err("Couldn't find path")?; }
			ret
		};
		let mut size: u64 = 0;
		sqfs_inode_get_file_size(inode, &mut size);
		println!("File is {} bytes", size);
		let data_reader = sqfs_data_reader_create(file, superblock.block_size as u64, compressor, 0);
		if data_reader.is_null() { sfs_err("Couldn't create data reader")?; }
		sfs_check(sqfs_data_reader_load_fragment_table(data_reader, &superblock), "Couldn't create data reader")?;
		let mut off = 0 as u64;
		let mut content = String::new();
		let mut buf: Vec<u8> = vec![0; 10];
		loop {
			let readres = sfs_check(sqfs_data_reader_read(data_reader, inode, off, buf.as_mut_ptr() as *mut libc::c_void, buf.len() as u32), "Couldn't read file content")?;
			if readres == 0 { break; }
			content.push_str(&String::from_utf8_lossy(&buf[0..readres as usize]));
			off += readres as u64;
		}
		println!("{}", content);
		let xattr_reader = sqfs_xattr_reader_create(0);
		sfs_check(sqfs_xattr_reader_load(xattr_reader, &superblock, file, compressor), "Couldn't create xattr reader")?;
		let mut xattr_idx: u32 = NO_XATTRS;
		sfs_check(sqfs_inode_get_xattr_index(inode, &mut xattr_idx), "Couldn't get xattr index")?;
		let xattr_id = {
			let mut ret: MaybeUninit<sqfs_xattr_id_t> = MaybeUninit::uninit();
			sfs_check(sqfs_xattr_reader_get_desc(xattr_reader, xattr_idx, ret.as_mut_ptr()), "Couldn't get xattr descriptor")?;
			ret.assume_init()
		};
		let xattr_type = SQFS_XATTR_TYPE_SQFS_XATTR_USER;
		let mut xattrs: HashMap<Vec<u8>, Vec<u8>> = HashMap::new();
		sfs_check(sqfs_xattr_reader_seek_kv(xattr_reader, &xattr_id), "Couldn't seek to xattr location")?;
		for _ in 0..xattr_id.count {
			let mut xattr_key: *mut sqfs_xattr_entry_t = ptr::null_mut();
			sfs_check(sqfs_xattr_reader_read_key(xattr_reader, &mut xattr_key), "Couldn't read xattr key")?;
			if xattr_key.is_null() { sfs_err("Couldn't read xattr key")?; }
			if (*xattr_key).type_ as u32 & SQFS_XATTR_TYPE_SQFS_XATTR_FLAG_OOL != 0 {
				// TODO
			}
			let prefixlen = CStr::from_ptr(sqfs_get_xattr_prefix((*xattr_key).type_ as u32)).to_bytes().len();
			let mut xattr_val: *mut sqfs_xattr_value_t = ptr::null_mut();
			sfs_check(sqfs_xattr_reader_read_value(xattr_reader, xattr_key, &mut xattr_val), "Couldn't read xattr value")?;
			if xattr_val.is_null() { sfs_err("Couldn't read xattr value")?; }
			if (*xattr_key).type_ as u32 & SQFS_XATTR_TYPE_SQFS_XATTR_PREFIX_MASK == xattr_type {
				let keyvec = (*xattr_key).key.as_slice((*xattr_key).size as usize + prefixlen)[prefixlen..].to_vec();
				let valvec = (*xattr_val).value.as_slice((*xattr_val).size as usize).to_vec();
				xattrs.insert(keyvec, valvec);
			}
			libc::free(xattr_val as *mut libc::c_void);
			libc::free(xattr_key as *mut libc::c_void);
		}
		for (key, val) in xattrs {
			println!("xattr {}: {}", String::from_utf8_lossy(&key), String::from_utf8_lossy(&val));
		}
		sfs_destroy(xattr_reader as *mut sqfs_object_t);
		sfs_destroy(data_reader as *mut sqfs_object_t);
		libc::free(inode as *mut libc::c_void);
		libc::free(dir_entry as *mut libc::c_void);
		libc::free(root as *mut libc::c_void);
		sfs_destroy(dir_reader as *mut sqfs_object_t);
		sfs_destroy(file as *mut sqfs_object_t);
		Ok(())
	}
}

pub fn test() -> Result<()> {
	let fname = "/home/matt/Scratch/wikivoyage.sfs";
	let a = Archive::new(fname)?;
	let root = a.get("")?;
	for entry in root.as_dir().unwrap() {
		println!("{}", entry.name());
	}
	let node = a.get("_meta/info.lua")?;
	let mut file = node.as_file().unwrap();
	println!("File {} is {} bytes", node.path().display(), file.size());
	let mut content = "".to_string();
	file.read_to_string(&mut content).unwrap();
	println!("{}", content);
	for (k, v) in node.xattrs(XattrType::User)? {
		println!("{}: {}", String::from_utf8_lossy(&k), String::from_utf8_lossy(&v));
	}
	let link = a.get("index.html")?;
	println!("{} points to {}", link, link.resolve()?);
	Ok(())
}
