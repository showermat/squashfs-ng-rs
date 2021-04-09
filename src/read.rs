//! Facilities for reading SquashFS archives.
//!
//! The most common scenario for using this library is:
//!
//!  1. To open a SquashFS file, use [`Archive::new`].
//!  2. Call [`get`](Archive::get) to retrieve a [`Node`] by its path.
//!  3. Call [`data`](Node::data) to get a [`Data`] object containing the node's data.
//!
//! `Node` also provides methods for inspecting metadata, resolving symlinks, and conveniently
//! converting to file and directory objects.
//!
//!     let archive = Archive::open("archive.sfs")?;
//!     match archive.get("/etc/passwd")? {
//!         None => println!("File not present"),
//!         Some(node) => if let Data::File(file) = node.data()? {
//!             println!("{}", file.to_string()?);
//!         },
//!     }

use std::collections::{HashMap, HashSet};
use std::ffi::{CStr, CString};
use std::io;
use std::io::{Read, Seek};
use std::mem::ManuallyDrop;
use std::ops::{Deref, DerefMut};
use std::path::{Path, PathBuf, Component};
use std::sync::{Arc, Mutex};
use super::*;
use memmap::{Mmap, MmapOptions};
use owning_ref::OwningHandle;

// Canonicalize without requiring the path to actually exist in the filesystem
fn dumb_canonicalize(path: &Path) -> PathBuf {
	let mut ret = PathBuf::new();
	for part in path.components() {
		match part {
			Component::Prefix(_) => (),
			Component::CurDir => (),
			Component::RootDir => ret.clear(),
			Component::ParentDir => { ret.pop(); },
			Component::Normal(p) => ret.push(p),
		}
	}
	ret
}

// Pass errors through, but convert missing file errors to None
fn enoent_ok<T>(t: Result<T>) -> Result<Option<T>> {
	match t {
		Ok(ret) => Ok(Some(ret)),
		Err(SquashfsError::LibraryError(_, LibError::NoEntry)) => Ok(None),
		Err(e) => Err(e),
	}
}

// Wrapper for leasing objects from a pool
struct Leased<'a, T> {
	pool: &'a Mutex<Vec<T>>,
	data: ManuallyDrop<T>,
}

impl<'a, T> Leased<'a, T> {
	pub fn new(pool: &'a Mutex<Vec<T>>, data: T) -> Self {
		Self { pool: pool, data: ManuallyDrop::new(data) }
	}
}

impl<'a, T> Deref for Leased<'a, T> {
	type Target = T;

	fn deref(&self) -> &Self::Target {
		&self.data
	}
}

impl<'a, T> DerefMut for Leased<'a, T> {
	fn deref_mut(&mut self) -> &mut Self::Target {
		&mut self.data
	}
}

impl<'a, T> Drop for Leased<'a, T> {
	fn drop(&mut self) {
		unsafe { self.pool.lock().expect(LOCK_ERR).push(ManuallyDrop::take(&mut self.data)); }
	}
}

/// A directory in the archive.
///
/// Directory objects are obtained by calling the [`data`](Node::data) or [`as_dir`](Node::as_dir)
/// method on a [`Node`] object.  `Dir` implements [`Iterator`](std::iter::Iterator), so all
/// children can be retrieved just by iterating over the directory.  The iterator can be reset by
/// calling [`reset`](Self::reset).  Individual children can also be retrieved by name using
/// [`child`](Self::child).
///
///     let archive = Archive::new("archive.sfs")?;
///     let node = archive.get("/my-dir")?.expect("/my-dir does not exist").resolve()?;
///     let dir = node.as_dir()?;
///     let child = dir.child("file.txt")?.expect("/my-dir/file.txt does not exist");
///     for entry in dir {
///         println!("{}", entry?.name().unwrap());
///     }
#[derive(Debug)]
pub struct Dir<'a> {
	node: &'a Node<'a>,
	compressor: ManagedPointer<sqfs_compressor_t>,
	reader: Mutex<ManagedPointer<sqfs_dir_reader_t>>,
}

impl<'a> Dir<'a> {
	fn new(node: &'a Node) -> Result<Self> {
		let compressor = node.container.compressor()?;
		let reader = sfs_init_check_null(&|| unsafe {
			sqfs_dir_reader_create(&node.container.superblock, *compressor, *node.container.file, 0)
		}, "Couldn't create directory reader", sfs_destroy)?;
		unsafe { sfs_check(sqfs_dir_reader_open_dir(*reader, node.inode.as_const(), 0), "Couldn't open directory")?; }
		Ok(Self { node: node, compressor: compressor, reader: Mutex::new(reader) })
	}

	/// Reset the directory reader to the beginning of the directory.
	///
	/// If the directory has been partially or completely iterated through, this will put it back
	/// to the beginning so that it can be read again.
	pub fn reset(&mut self) {
		unsafe { sqfs_dir_reader_rewind(**self.reader.lock().expect(LOCK_ERR)); }
	}

	fn read<'b>(&'b self) -> Result<Option<Node<'a>>> {
		let locked_reader = self.reader.lock().expect(LOCK_ERR);
		let mut raw_entry: *mut sqfs_dir_entry_t = ptr::null_mut();
		if sfs_check(unsafe { sqfs_dir_reader_read(**locked_reader, &mut raw_entry) }, "Couldn't read directory entries")? > 0 { Ok(None) }
		else if raw_entry.is_null() { Err(SquashfsError::LibraryReturnError("Couldn't read directory entries".to_string()))? }
		else {
			let entry = ManagedPointer::new(raw_entry, libc_free);
			let name_bytes = unsafe { (**entry).name.as_slice((**entry).size as usize + 1) };
			let name = String::from_utf8(name_bytes.to_vec())?;
			let node = sfs_init_ptr(&|x| unsafe {
				sqfs_dir_reader_get_inode(**locked_reader, x)
			}, "Couldn't read directory entry inode", libc_free)?;
			Ok(Some(Node::new(self.node.container, node, self.node.path.as_ref().map(|path| path.join(name)))?))
		}
	}

	/// Select a child inside the directory by name.
	///
	/// This will return `Ok(None)` if the child does not exist, or an `Err` if the lookup could
	/// not be performed.
	pub fn child(&self, name: &str) -> Result<Option<Node>> {
		match unsafe { enoent_ok(sfs_check(sqfs_dir_reader_find(**self.reader.lock().expect(LOCK_ERR), CString::new(name)?.as_ptr()), &format!("Couldn't find child \"{}\"", name)))? } {
			None => Ok(None),
			Some(_) => Ok(self.read()?),
		}
	}
}

impl<'a> std::iter::Iterator for Dir<'a> {
	type Item = Result<Node<'a>>;

	fn next(&mut self) -> Option<Self::Item> {
		self.read().transpose()
	}
}

struct DataReader {
	#[allow(dead_code)] compressor: ManagedPointer<sqfs_compressor_t>, // Referenced by `reader`
	reader: ManagedPointer<sqfs_data_reader_t>,
}

impl<'a> DataReader {
	fn new(archive: &'a Archive) -> Result<Self> {
		let compressor = archive.compressor()?;
		let reader = sfs_init_check_null(&|| unsafe {
			sqfs_data_reader_create(*archive.file, archive.superblock.block_size as u64, *compressor, 0)
		}, "Couldn't create data reader", sfs_destroy)?;
		unsafe { sfs_check(sqfs_data_reader_load_fragment_table(*reader, &archive.superblock), "Couldn't load fragment table")? };
		Ok(Self { compressor: compressor, reader: reader })
	}

	fn read(&self, inode: &ManagedPointer<sqfs_inode_generic_t>, offset: u64, buf: &mut [u8]) -> io::Result<u64> {
		Ok(unsafe { sfs_check(
			sqfs_data_reader_read(*self.reader, inode.as_const(), offset, buf.as_mut_ptr() as *mut libc::c_void, buf.len() as u32),
			"Couldn't read file content"
		).map_err(|e| io::Error::new(io::ErrorKind::Other, e))? } as u64)
	}
}

/// A file in the archive.
///
/// `File` objects allow standard operations on file inodes in an archive.  `File` implements
/// [`Read`] and [`Seek`], so anything that reads files using standard Rust semantics can interact
/// natively with these files.  [`to_bytes`](Self::to_bytes) and [`to_string`](Self::to_string)
/// offer convenience wrappers around this.  Files that were archived with compression and
/// fragmentation disabled can also be [`mmap`](Self::mmap)ed and accessed as an ordinary byte
/// array.
///
///     let archive = Archive::new("archive.sfs")?;
///     let node = archive.get("/a/01.txt")?.unwrap().resolve()?;
///     let file = node.as_file()?;
///     // File can now be used like anything else that implements `Read` and `Seek`.
///     let mut buf = [0; 10];
///     file.seek(SeekFrom::End(-10))?;
///     file.read(&mut buf)?;
pub struct File<'a> {
	node: &'a Node<'a>,
	offset: Mutex<u64>,
}

impl<'a> File<'a> {
	fn new(node: &'a Node) -> Result<Self> {
		Ok(Self { node: node, offset: Mutex::new(0) })
	}

	/// Retrieve the size of the file in bytes.
	pub fn size(&self) -> u64 {
		let mut ret: u64 = 0;
		unsafe { sqfs_inode_get_file_size(self.node.inode.as_const(), &mut ret) };
		ret
	}

	/// Retrieve the entire contents of the file in the form of a byte Vec.
	pub fn to_bytes(&mut self) -> Result<Vec<u8>> {
		let mut ret = Vec::with_capacity(self.size() as usize);
		self.read_to_end(&mut ret)?;
		Ok(ret)
	}

	/// Retrieve the entire contents of the file in the form of a String.
	///
	/// This calls [`Read::read_to_string`] under the hood.  Consequently, a UTF-8 error
	/// will be raised if the entire file is not valid UTF-8.
	pub fn to_string(&mut self) -> Result<String> {
		let mut ret = String::with_capacity(self.size() as usize);
		self.read_to_string(&mut ret)?;
		Ok(ret)
	}

	/// Map a file into memory for fast parallel random access.
	///
	/// This uses `mmap` to map the file into memory.  **It will fail** and return `None` if the
	/// file is compressed or fragmented.  If the [`DontCompress`](write::BlockFlags::DontCompress)
	/// and [`DontFragment`](write::BlockFlags::DontFragment) options are set for a file at
	/// archive creation time, it will be added to the archive in one contiguous unmodified chunk.
	/// This is necessary because `mmap` provides a view into a file exactly as it is on-disk;
	/// there is no opportunity for the library to apply decompression or other transformations
	/// when mapping.
	///
	///     let map = file.mmap().expect("File is not mmappable");
	///     println!("{}", str::from_utf8(map)?);
	pub fn mmap<'b>(&'b mut self) -> Option<&'b [u8]> {
		let inode = unsafe { &***self.node.inode };
		let (start, frag_idx) = unsafe {
			match inode.base.type_ as u32 {
				SQFS_INODE_TYPE_SQFS_INODE_FILE => (inode.data.file.blocks_start as u64, inode.data.file.fragment_index),
				SQFS_INODE_TYPE_SQFS_INODE_EXT_FILE => (inode.data.file_ext.blocks_start, inode.data.file_ext.fragment_idx),
				_ => panic!("File is not a file")
			}
		};
		let block_count = inode.payload_bytes_used / std::mem::size_of::<sqfs_u32>() as u32;
		if block_count == 0 || frag_idx != 0xffffffff { return None; }
		let block_sizes = unsafe { inode.extra.as_slice(block_count as usize) };
		if block_sizes.iter().any(|x| x & 0x01000000 == 0) { return None; }
		Some(self.node.container.map_range(start as usize, self.size() as usize))
	}
}

impl<'a> Read for File<'a> {
	fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
		let mut locked_offset = self.offset.lock().expect(LOCK_ERR);
		if *locked_offset >= self.size() { Ok(0) }
		else {
			let res = self.node.container.data_reader().unwrap().read(&self.node.inode, *locked_offset, buf)?;
			*locked_offset += res;
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

impl<'a> std::fmt::Debug for File<'a> {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		write!(f, "File at {:?}", self.node)
	}
}

/// Enum type for the various kinds of data that an inode can be.
///
/// This is retrieved by calling [`Node::data`] and can be matched to determine the type and
/// contents of a node.
///
/// For accessing files and directories, [`Node`] provides the [`as_dir`](Node::as_dir) and
/// [`as_file`](Node::as_file) methods to bypass `Data` completely.
#[derive(Debug)]
pub enum Data<'a> {
	/// A regular file, containing a [`File`] object that can be used to extract the file contents.
	File(File<'a>),

	/// A directory, containing a [`Dir`] that can be used to access the directory's children.
	Dir(Dir<'a>),

	/// A symbolic link, containing the target of the link as a [`PathBuf`].
	Symlink(PathBuf),

	/// A block device file, containing the device's major and minor numbers.
	BlockDev(u32, u32),

	/// A character device file, containing the device's major and minor numbers.
	CharDev(u32, u32),

	/// A named pipe.
	Fifo,

	/// A socket.
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
				let path_str = arr_to_string(&(***node.inode).extra, (***node.inode).data.slink.target_size as usize);
				Self::Symlink(PathBuf::from(path_str))
			}),
			SQFS_INODE_TYPE_SQFS_INODE_EXT_SLINK => Ok(unsafe {
				let path_str = arr_to_string(&(***node.inode).extra, (***node.inode).data.slink_ext.target_size as usize);
				Self::Symlink(PathBuf::from(path_str))
			}),
			SQFS_INODE_TYPE_SQFS_INODE_BDEV => Ok(unsafe {
				let (maj, min) = get_dev_nums((***node.inode).data.dev.devno);
				Self::BlockDev(maj, min)
			}),
			SQFS_INODE_TYPE_SQFS_INODE_EXT_BDEV => Ok(unsafe {
				let (maj, min) = get_dev_nums((***node.inode).data.dev_ext.devno);
				Self::BlockDev(maj, min)
			}),
			SQFS_INODE_TYPE_SQFS_INODE_CDEV => Ok(unsafe {
				let (maj, min) = get_dev_nums((***node.inode).data.dev.devno);
				Self::CharDev(maj, min)
			}),
			SQFS_INODE_TYPE_SQFS_INODE_EXT_CDEV => Ok(unsafe {
				let (maj, min) = get_dev_nums((***node.inode).data.dev_ext.devno);
				Self::CharDev(maj, min)
			}),
			SQFS_INODE_TYPE_SQFS_INODE_FIFO | SQFS_INODE_TYPE_SQFS_INODE_EXT_FIFO  => Ok(Self::Fifo),
			SQFS_INODE_TYPE_SQFS_INODE_SOCKET | SQFS_INODE_TYPE_SQFS_INODE_EXT_SOCKET  => Ok(Self::Socket),
			_ => Err(SquashfsError::LibraryReturnError("Unsupported inode type".to_string())),
		}
	}
	
	/// Get a human-readable English name for the type of file represented by this object, intended
	/// primarily for debugging.
	pub fn name(&self) -> String {
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

/// Represents the namespace of extended attributes.
#[repr(u32)]
#[derive(Clone, Copy)]
pub enum XattrType {
	User = SQFS_XATTR_TYPE_SQFS_XATTR_USER,
	Trusted = SQFS_XATTR_TYPE_SQFS_XATTR_TRUSTED,
	Security = SQFS_XATTR_TYPE_SQFS_XATTR_SECURITY,
}

/// An object packaging a [`File`] with the [`Node`] from which it was constructed.
///
/// `File`s reference data in the `Node` objects that created them, so a `File` cannot be used
/// after its corresponding `Node` has been dropped.  This object packages the two together,
/// creating an object that is valid for the lifetime of the owning `Archive`.
///
/// This is a simple wrapper around an [`OwningHandle`] that re-implements the [`Read`] and
/// [`Seek`] traits so that it can still be treated as a file.  [`Deref`](std::ops::Deref) and
/// [`DerefMut`](std::ops::DerefMut) are also available to access the contained file.
///
/// Create an `OwnedFile` using [`Node::into_owned_file`].
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

/// An object packaging a [`Dir`] with the [`Node`] from which it was constructed.
///
/// `Dir`s retain references to the `Node`s that created them, so a `Dir` cannot be used after its
/// corresponding `Node` has been dropped.  `OwnedDir` packages the two together, creating an
/// independent object with the same lifetime as its owning `Archive`.
///
/// `OwnedDir` re-implements [`Iterator`](std::iter::Iterator) so that it can be iterated over just
/// like `Dir`.  It also implements [`Deref`](std::ops::Deref) and [`DerefMut`](std::ops::DerefMut)
/// to allow access to the internal `Dir`.
pub struct OwnedDir<'a> {
	handle: OwningHandle<Box<Node<'a>>, Box<Dir<'a>>>,
}

impl<'a> std::iter::Iterator for OwnedDir<'a> {
	type Item = Result<Node<'a>>;

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

/// Information about a single node in the directory tree.
///
/// This corresponds to the inode and directory entry structures of the underlying library.
/// Because SquashFS inodes do not retain pointers back to their directory entries, inodes by
/// default have no information about their positions in the directory tree.  To work around this,
/// `Node` structs store their path and propagate it through calls like [`child`](Dir::child) and
/// [`parent`](Self::parent).  If the `Node` was originally constructed in a way that does not
/// provide path information, such as retrieving a node by inode number using [`Archive::get_id`],
/// then the methods that require knowledge of the node's location in the tree, such as
/// [`path`](Self::path) and [`parent`](Self::parent), will fail.  For this reason, it is generally
/// recommended to get nodes by path when possible.
pub struct Node<'a> {
	container: &'a Archive,
	path: Option<PathBuf>,
	inode: Arc<ManagedPointer<sqfs_inode_generic_t>>,
}

impl<'a> Node<'a> {
	fn new(container: &'a Archive, inode: ManagedPointer<sqfs_inode_generic_t>, path: Option<PathBuf>) -> Result<Self> {
		Ok(Self { container: container, path: path, inode: Arc::new(inode) })
	}

	/// Get a node's extended attributes in a given namespace as a map of byte Vecs.
	pub fn xattrs(&self, category: XattrType) -> Result<HashMap<Vec<u8>, Vec<u8>>> {
		if self.container.superblock.flags & SQFS_SUPER_FLAGS_SQFS_FLAG_NO_XATTRS as u16 != 0 { Ok(HashMap::new()) }
		// TODO The following line reflects what I think is a bug.  I have a non-xattr archive
		// created by mksquashfs, which does not have the above flag set but has the below table
		// offset of -1.  This workaround allows us to check both cases until I get around to
		// figuring out what's going on.
		else if self.container.superblock.xattr_id_table_start == 0xffffffffffffffff { Ok(HashMap::new()) }
		else {
			let compressor = self.container.compressor()?;
			let xattr_reader = sfs_init_check_null(&|| unsafe {
					sqfs_xattr_reader_create(0)
			}, "Coudn't create xattr reader", sfs_destroy)?;
			unsafe { sfs_check(sqfs_xattr_reader_load(*xattr_reader, &self.container.superblock, *self.container.file, *compressor), "Couldn't load xattr reader")?; }
			let mut xattr_idx: u32 = NO_XATTRS;
			unsafe { sfs_check(sqfs_inode_get_xattr_index(self.inode.as_const(), &mut xattr_idx), "Couldn't get xattr index")?; }
			let desc = sfs_init(&|x| unsafe {
				sqfs_xattr_reader_get_desc(*xattr_reader, xattr_idx, x)
			}, "Couldn't get xattr descriptor")?;
			let mut ret: HashMap<Vec<u8>, Vec<u8>> = HashMap::new();
			unsafe { sfs_check(sqfs_xattr_reader_seek_kv(*xattr_reader, &desc), "Couldn't seek to xattr location")? };
			for _ in 0..desc.count {
				let prefixlen = unsafe { CStr::from_ptr(sqfs_get_xattr_prefix(category as u32)).to_bytes().len() };
				let key = sfs_init_ptr(&|x| unsafe {
					sqfs_xattr_reader_read_key(*xattr_reader, x)
				}, "Couldn't read xattr key", libc_free)?;
				let val = sfs_init_ptr(&|x| unsafe {
					sqfs_xattr_reader_read_value(*xattr_reader, *key, x)
				}, "Couldn't read xattr value", libc_free)?;
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

	/// Get the inode number of a node.
	///
	/// This can be used to cheaply compare nodes for equality or can be later used with
	/// [`get_id`](Archive::get_id) to retrieve nodes without traversing the directory tree.
	pub fn id(&self) -> u32 {
		unsafe { (***self.inode).base.inode_number }
	}

	/// Retrieve the data stored at the node.
	pub fn data(&self) -> Result<Data> {
		Data::new(&self)
	}

	/// Get the absolute path to the node in the archive.
	///
	/// If the node was obtained in a way that did not provide path information, this will return
	/// `None`.  If the node was retrieved using [`Archive::get`], this should return `Some`.
	pub fn path(&self) -> Option<&Path> {
		self.path.as_ref().map(|path| path.as_path())
	}
	
	fn path_string(&self) -> String {
		match &self.path {
			Some(path) => path.display().to_string(), //os_to_string(path.as_os_str()),
			None => "<unknown>".to_string(),
		}
	}

	/// A convenience method to retrieve the file name of the node from its path.
	///
	/// As with [`path`](Self::path), if the node does not have embedded path information, this
	/// will return `None`.
	pub fn name(&self) -> Option<String> {
		self.path.as_ref().map(|path| path.file_name().map(|x| x.to_string_lossy().to_string()).unwrap_or("/".to_string()))
	}

	/// Get the parent directory node of the current node.
	///
	/// If the node is the root of the tree, it will return a copy of itself.  If this node was
	/// created without path information, it will raise a [`NoPath`](SquashfsError::NoPath) error.
	pub fn parent(&self) -> Result<Self> {
		self.path.as_ref().map(|path| {
			let ppath = path.parent().unwrap_or(&Path::new(""));
			self.container.get_exists(&os_to_string(ppath.as_os_str())?)
		}).ok_or(SquashfsError::NoPath)?
	}

	/// Resolve symbolic links to their targets, raising an error if a target does not exist.
	///
	/// This works the same way as [`resolve`](Self::resolve), except that an error is raised if
	/// any link in the chain of symbolic links points at a path that does not exist.
	pub fn resolve_exists(&self) -> Result<Self> {
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
					cur = Box::new(cur.container.get_exists(&target)?);
				}
				_ => return Ok(*cur),
			}
			i += 1;
			if i > LINK_MAX { Err(SquashfsError::LinkChain(LINK_MAX))?; }
		}
	}

	/// Resolve symbolic links to their targets.
	///
	/// This follows the chain of symbolic links starting at the current node all the way to the
	/// end, returning the final node, which is guaranteed not to be a symbolic link.  If any link
	/// in the chain points at a path that does not exist, it returns `Ok(None)`.  If the current
	/// node is not a sybmolic link, this returns a copy of itself.
	pub fn resolve(&self) -> Result<Option<Self>> {
		enoent_ok(self.resolve_exists())
	}

	/// Return true if the current `Node` is a file.
	///
	/// This does *not* resolve symbolic links, and will return `false` when called on nodes that
	/// are symbolic links to files.
	pub fn is_file(&self) -> Result<bool> {
		match self.data()? {
			Data::File(_) => Ok(true),
			_ => Ok(false),
		}
	}

	/// Fetch the [`File`] object from the current `Node`.
	///
	/// This is essentially a shortcut for `if let Data::File(file) = self.data()`.  If this node
	/// is not a regular file, this will return an error.  This does *not* resolve symbolic links;
	/// the caller should call [`resolve`](Self::resolve) first if the node could be a link.
	pub fn as_file(&self) -> Result<File> {
		match self.data()? {
			Data::File(f) => Ok(f),
			other => Err(SquashfsError::WrongType(self.path_string(), other.name(), "regular file".to_string())),
		}
	}
	
	/// Convert the `Node` into an [`OwnedFile`].
	///
	/// This resolves symbolic links.  If the current node is not a regular file or a link to one,
	/// it will return an error.
	///
	///     let archive = Archive::new("archive.sfs")?;
	///     let mut buf = String::new();
	///     archive.get("/file.txt")?.unwrap().into_owned_file()?.read_to_string(&mut buf)?;
	pub fn into_owned_file(self) -> Result<OwnedFile<'a>> {
		let resolved = self.resolve_exists()?;
		Ok(OwnedFile { handle: OwningHandle::try_new(Box::new(resolved), |x| unsafe { (*x).as_file().map(|x| Box::new(x)) })? })
	}

	/// Return true if the current `Node` is a directory.
	pub fn is_dir(&self) -> Result<bool> {
		match self.data()? {
			Data::Dir(_) => Ok(true),
			_ => Ok(false),
		}
	}

	/// Fetch the [`Dir`] object from the current `Node`.
	///
	/// This is essentially a shortcut for `if let Data::Dir(dir) = self.data()`.  If this node is
	/// not a directory, it will return an error.  This does *not* resolve symbolic links; the
	/// caller should call [`resolve`](Self::resolve) first if the node could be a link.
	pub fn as_dir(&self) -> Result<Dir> {
		match self.data()? {
			Data::Dir(d) => Ok(d),
			other => Err(SquashfsError::WrongType(self.path_string(), other.name(), "directory".to_string())),
		}
	}

	/// Convert the `Node` into an [`OwnedDir`].
	///
	/// This resolves symbolic links.  If the current node is not a directory or a link to one, it
	/// will return an error.
	///
	///     let archive = Archive::new("archive.sfs")?;
	///     for child in archive.get("/dir")?.unwrap().into_owned_dir()? {
	///         println!("{}", child?.name());
	///     }
	pub fn into_owned_dir(self) -> Result<OwnedDir<'a>> {
		let resolved = self.resolve_exists()?;
		Ok(OwnedDir { handle: OwningHandle::try_new(Box::new(resolved), |x| unsafe { (*x).as_dir().map(|x| Box::new(x)) })? })
	}

	/// Get the UID of the `Node`.
	pub fn uid(&self) -> Result<u32> {
		let idx = unsafe { (***self.inode).base.uid_idx };
		self.container.id_lookup(idx)
	}

	/// Get the GID of the `Node`.
	pub fn gid(&self) -> Result<u32> {
		let idx = unsafe { (***self.inode).base.gid_idx };
		self.container.id_lookup(idx)
	}

	/// Get the file mode of the `Node`.
	pub fn mode(&self) -> u16 {
		unsafe { (***self.inode).base.mode }
	}

	/// Get the modification time of the `Node` as a UNIX timestamp.
	pub fn mtime(&self) -> u32 {
		unsafe { (***self.inode).base.mod_time }
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

/// An open SquashFS archive.
pub struct Archive {
	path: PathBuf,
	file: ManagedPointer<sqfs_file_t>,
	superblock: sqfs_super_t,
	compressor_config: sqfs_compressor_config_t,
	mmap: (std::fs::File, Mmap),
	data_readers: Mutex<Vec<DataReader>>,
}

impl Archive {
	/// Open an existing archive for reading.
	pub fn new<T: AsRef<Path>>(path: T) -> Result<Self> {
		let cpath = CString::new(os_to_string(path.as_ref().as_os_str())?)?;
		let file = sfs_init_check_null(&|| unsafe {
			sqfs_open_file(cpath.as_ptr(), SQFS_FILE_OPEN_FLAGS_SQFS_FILE_OPEN_READ_ONLY)
		}, &format!("Couldn't open input file {}", path.as_ref().display()), sfs_destroy)?;
		let superblock = sfs_init(&|x| unsafe {
			sqfs_super_read(x, *file)
		}, "Couldn't read archive superblock")?;
		let compressor_config = sfs_init(&|x| unsafe {
			sqfs_compressor_config_init(x, superblock.compression_id as u32, superblock.block_size as u64, SQFS_COMP_FLAG_SQFS_COMP_FLAG_UNCOMPRESS as u16)
		}, "Couldn't read archive compressor config")?;
		let os_file = std::fs::File::open(&path)?;
		let map = unsafe { MmapOptions::new().map(&os_file).map_err(|e| SquashfsError::Mmap(e))? };
		//let map = MemoryMap::new(superblock.bytes_used as usize, &vec![MapOption::MapReadable, MapOption::MapFd(os_file.as_raw_fd())])?;
		Ok(Self { path: path.as_ref().to_path_buf(), file: file, superblock: superblock, compressor_config: compressor_config, mmap: (os_file, map), data_readers: Mutex::new(vec![]) })
	}

	fn compressor(&self) -> Result<ManagedPointer<sqfs_compressor_t>> {
		Ok(sfs_init_ptr(&|x| unsafe {
			sqfs_compressor_create(&self.compressor_config, x)
		}, "Couldn't create compressor", sfs_destroy)?)
	}

	fn meta_reader(&self, compressor: &ManagedPointer<sqfs_compressor_t>, bounds: Option<(u64, u64)>) -> Result<ManagedPointer<sqfs_meta_reader_t>> {
		let range = bounds.unwrap_or((0, self.superblock.bytes_used));
		Ok(sfs_init_check_null(&|| unsafe {
			sqfs_meta_reader_create(*self.file, **compressor, range.0, range.1)
		}, "Couldn't create metadata reader", sfs_destroy)?)
	}

	fn data_reader(&self) -> Result<Leased<DataReader>> {
		let mut locked_readers = self.data_readers.lock().expect(LOCK_ERR);
		let ret = match locked_readers.pop() {
			Some(reader) => reader,
			None => { println!("Made data reader"); DataReader::new(&self)? },
		};
		Ok(Leased::new(&self.data_readers, ret))
	}

	fn id_lookup(&self, idx: u16) -> Result<u32> {
		let id_table = sfs_init_check_null(&|| unsafe {
			sqfs_id_table_create(0)
		}, "Couldn't create ID table", sfs_destroy)?;
		let compressor = self.compressor()?;
		unsafe { sfs_check(sqfs_id_table_read(*id_table, *self.file, &self.superblock, *compressor), "Couldn't read ID table")?; }
		Ok(sfs_init(&|x| unsafe {
			sqfs_id_table_index_to_id(*id_table, idx, x)
		}, "Couldn't get ID from ID table")?)
	}

	/// Retrieve the path with that was used to open the archive.
	pub fn path(&self) -> &Path {
		&self.path
	}

	/// Get the number of inodes in the archive.
	pub fn size(&self) -> u32 {
		self.superblock.inode_count
	}

	/// Get the [`Node`] located at the given path, raising an error if it does not exist.
	pub fn get_exists<T: AsRef<Path>>(&self, path: T) -> Result<Node> {
		let compressor = self.compressor()?;
		let dir_reader = sfs_init_check_null(&|| unsafe {
			sqfs_dir_reader_create(&self.superblock, *compressor, *self.file, 0)
		}, "Couldn't create directory reader", sfs_destroy)?;
		let root = sfs_init_ptr(&|x| unsafe {
			sqfs_dir_reader_get_root_inode(*dir_reader, x)
		}, "Couldn't get filesystem root", libc_free)?;
		let pathbuf = dumb_canonicalize(path.as_ref());
		if &pathbuf == Path::new("/") {
			Node::new(&self, root, Some(pathbuf))
		}
		else {
			let cpath = CString::new(os_to_string(pathbuf.as_os_str())?)?;
			let inode = sfs_init_ptr(&|x| unsafe {
				sqfs_dir_reader_find_by_path(*dir_reader, *root, cpath.as_ptr(), x)
			}, &format!("Unable to access path {}", path.as_ref().display()), libc_free)?;
			Node::new(&self, inode, Some(pathbuf))
		}
	}

	/// Get the [`Node`] located at the given path in the archive.
	///
	/// If the path is not present, `Ok(None)` will be returned.
	pub fn get<T: AsRef<Path>>(&self, path: T) -> Result<Option<Node>> {
		enoent_ok(self.get_exists(path))
	}

	/// Get a node from the archive by its inode number.
	///
	/// Each inode in an archive has a unique ID.  If the archive was created with the "exportable"
	/// option (intended for exporting over NFS), it is efficient to look up inodes by their IDs.
	/// If this archive is not exportable, [`SquashfsError::Unsupported`] will be raised.  A `Node`
	/// obtained in this way will lack path information, and as such operations like getting its
	/// file name or parent will fail.
	pub fn get_id(&self, id: u64) -> Result<Node> {
		if self.superblock.flags & SQFS_SUPER_FLAGS_SQFS_FLAG_EXPORTABLE as u16 == 0 { Err(SquashfsError::Unsupported("inode indexing".to_string()))?; }
		if id <= 0 || id > self.superblock.inode_count as u64 { Err(SquashfsError::Range(id, self.superblock.inode_count as u64))? }
		let compressor = self.compressor()?;
		let export_reader = self.meta_reader(&compressor, None)?; // Would be nice if we could set bounds for this
		let (block, offset) = ((id - 1) / 1024, (id - 1) % 1024 * 8);
		let block_start: u64 = sfs_init(&|x| unsafe {
			let read_at = (**self.file).read_at.expect("File object does not implement read_at");
			read_at(*self.file, self.superblock.export_table_start + block * 8, x as *mut libc::c_void, 8)
		}, "Couldn't read inode table")?;

		let mut noderef: u64 = 0;
		unsafe {
			sfs_check(sqfs_meta_reader_seek(*export_reader, block_start, offset), "Couldn't seek to inode reference")?;
			sfs_check(sqfs_meta_reader_read(*export_reader, &mut noderef as *mut u64 as *mut libc::c_void, 8), "Couldn't read inode reference")?;
		}
		let (block, offset) = unpack_meta_ref(noderef);
		let inode = sfs_init_ptr(&|x| unsafe {
			sqfs_meta_reader_read_inode(*export_reader, &self.superblock, block, offset, x)
		}, "Couldn't read inode", libc_free)?;
		Node::new(&self, inode, None)
	}

	fn map_range(&self, start: usize, len: usize) -> &[u8] {
		&(self.mmap.1)[start..start + len]
	}
}

unsafe impl Send for Archive { }
unsafe impl Sync for Archive { }
