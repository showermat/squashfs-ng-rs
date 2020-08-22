use std::collections::{HashMap, HashSet};
use std::ffi::{CStr, CString, OsStr, OsString};
use std::io;
use std::io::{Read, Seek};
use std::path::{Path, PathBuf, Component};
use std::os::unix::io::AsRawFd; // TODO Is there a way to mmap cross-platform?
use std::sync::{Arc, Mutex};
use bindings::*;
use super::*;
use mmap::{MemoryMap, MapOption};
use owning_ref::OwningHandle;
use thiserror::Error;

// Canonicalize without requiring the path to actually exist in the filesystem
fn dumb_canonicalize(path: &Path) -> PathBuf {
	let mut ret = PathBuf::new();
	for part in path.components() {
		match part {
			Component::Prefix(_) => panic!("What is this, Windows?"), // TODO
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

	pub fn reset(&mut self) {
		unsafe { sqfs_dir_reader_rewind(**self.reader.lock().expect(LOCK_ERR)); }
	}

	fn read<'b>(&'b self) -> Result<Node<'a>> {
		let locked_reader = self.reader.lock().expect(LOCK_ERR);
		let entry = sfs_init_ptr(&|x| unsafe {
			sqfs_dir_reader_read(**locked_reader, x)
		}, "Couldn't read directory entries", libc_free)?;
		let name_bytes = unsafe { (**entry).name.as_slice((**entry).size as usize + 1) };
		let name = String::from_utf8(name_bytes.to_vec())?;
		let node = sfs_init_ptr(&|x| unsafe {
			sqfs_dir_reader_get_inode(**locked_reader, x)
		}, "Couldn't read directory entry inode", libc_free)?;
		Node::new(self.node.container, node, self.node.path.as_ref().map(|path| path.join(name)))
	}

	pub fn child(&self, name: &str) -> Result<Option<Node>> {
		match unsafe { enoent_ok(sfs_check(sqfs_dir_reader_find(**self.reader.lock().expect(LOCK_ERR), CString::new(name)?.as_ptr()), &format!("Couldn't find child \"{}\"", name)))? } {
			None => Ok(None),
			Some(_) => Ok(Some(self.read()?)),
		}
	}
}

impl<'a> std::iter::Iterator for Dir<'a> {
	type Item = Node<'a>;

	fn next(&mut self) -> Option<Self::Item> {
		self.read().ok()
	}
}

pub struct File<'a> {
	node: &'a Node<'a>,
	compressor: ManagedPointer<sqfs_compressor_t>,
	reader: Mutex<ManagedPointer<sqfs_data_reader_t>>,
	offset: Mutex<u64>,
}

impl<'a> File<'a> {
	fn new(node: &'a Node) -> Result<Self> {
		let compressor = node.container.compressor()?;
		let reader = sfs_init_check_null(&|| unsafe {
			sqfs_data_reader_create(*node.container.file, node.container.superblock.block_size as u64, *compressor, 0)
		}, "Couldn't create data reader", sfs_destroy)?;
		unsafe { sfs_check(sqfs_data_reader_load_fragment_table(*reader, &node.container.superblock), "Couldn't load fragment table")? };
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

	pub fn mmap<'b>(&'b mut self) -> Option<&'b [u8]> {
		let inode = unsafe { &***self.node.inode };
		let (start, frag_idx) = unsafe {
			match inode.base.type_ as u32 {
				SQFS_INODE_TYPE_SQFS_INODE_FILE => (inode.data.file.blocks_start as u64, inode.data.file.fragment_index),
				SQFS_INODE_TYPE_SQFS_INODE_EXT_FILE => (inode.data.file_ext.blocks_start, inode.data.file_ext.fragment_idx),
				_ => panic!("File is not a file")
			}
		};
		let block_count = unsafe { inode.payload_bytes_used / std::mem::size_of::<sqfs_u32>() as u32 };
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

impl<'a> std::fmt::Debug for File<'a> {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		write!(f, "File at {:?}", self.node)
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
			Some(path) => path.display().to_string(), //os_to_string(path.as_os_str()),
			None => "<unknown>".to_string(),
		}
	}

	pub fn name(&self) -> Option<String> {
		self.path.as_ref().map(|path| path.file_name().map(|x| x.to_string_lossy().to_string()).unwrap_or("/".to_string()))
	}

	pub fn parent(&self) -> Result<Self> {
		self.path.as_ref().map(|path| {
			let ppath = path.parent().unwrap_or(&Path::new(""));
			self.container.get_exists(&os_to_string(ppath.as_os_str())?)
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
					cur = Box::new(cur.container.get_exists(&target)?);
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
		let resolved = self.resolve()?;
		Ok(OwnedFile { handle: OwningHandle::try_new(Box::new(resolved), |x| unsafe { (*x).as_file().map(|x| Box::new(x)) })? })
	}

	pub fn as_dir(&self) -> Result<Dir> {
		match self.data()? {
			Data::Dir(d) => Ok(d),
			other => Err(SquashfsError::WrongType(self.path_string(), other.name(), "directory".to_string())),
		}
	}

	pub fn into_owned_dir(self) -> Result<OwnedDir<'a>> {
		let resolved = self.resolve()?;
		Ok(OwnedDir { handle: OwningHandle::try_new(Box::new(resolved), |x| unsafe { (*x).as_dir().map(|x| Box::new(x)) })? })
	}

	pub fn uid(&self) -> Result<u32> {
		let idx = unsafe { (***self.inode).base.uid_idx };
		self.container.id_lookup(idx)
	}

	pub fn gid(&self) -> Result<u32> {
		let idx = unsafe { (***self.inode).base.gid_idx };
		self.container.id_lookup(idx)
	}

	pub fn mode(&self) -> u16 {
		unsafe { (***self.inode).base.mode }
	}

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

pub struct Archive {
	path: PathBuf,
	file: ManagedPointer<sqfs_file_t>,
	superblock: sqfs_super_t,
	compressor_config: sqfs_compressor_config_t,
	mmap: (std::fs::File, MemoryMap),
}

impl Archive {
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
		let map = MemoryMap::new(superblock.bytes_used as usize, &vec![MapOption::MapReadable, MapOption::MapFd(os_file.as_raw_fd())])?;
		Ok(Self { path: path.as_ref().to_path_buf(), file: file, superblock: superblock, compressor_config: compressor_config, mmap: (os_file, map) })
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

	fn id_lookup(&self, idx: u16) -> Result<u32> {
		// TODO Consider chaching the ID table to make lookups more efficient
		let mut id_table = sfs_init_check_null(&|| unsafe {
			sqfs_id_table_create(0)
		}, "Couldn't create ID table", sfs_destroy)?;
		let compressor = self.compressor()?;
		unsafe { sfs_check(sqfs_id_table_read(*id_table, *self.file, &self.superblock, *compressor), "Couldn't read ID table")?; }
		Ok(sfs_init(&|x| unsafe {
			sqfs_id_table_index_to_id(*id_table, idx, x)
		}, "Couldn't get ID from ID table")?)
	}

	pub fn size(&self) -> u32 {
		self.superblock.inode_count
	}

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

	pub fn get<T: AsRef<Path>>(&self, path: T) -> Result<Option<Node>> {
		enoent_ok(self.get_exists(path))
	}

	pub fn get_id(&self, id: u64) -> Result<Node> { // TODO Return Result<Option<Node>> here as well
		if self.superblock.flags & SQFS_SUPER_FLAGS_SQFS_FLAG_EXPORTABLE as u16 == 0 { Err(SquashfsError::Unsupported("inode indexing".to_string()))?; }
		if id <= 0 || id > self.superblock.inode_count as u64 { Err(SquashfsError::Range(id, self.superblock.inode_count as u64))? }
		let compressor = self.compressor()?;
		let export_reader = self.meta_reader(&compressor, None)?; // TODO Would be nice if we could set bounds for this
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
		let (block, offset) = unpack_meta_ref(noderef);
		let inode = sfs_init_ptr(&|x| unsafe {
			sqfs_meta_reader_read_inode(*export_reader, &self.superblock, block, offset, x)
		}, "Couldn't read inode", libc_free)?;
		Node::new(&self, inode, None)
	}

	fn map_range(&self, start: usize, len: usize) -> &[u8] {
		let map = &self.mmap.1;
		unsafe { std::slice::from_raw_parts(map.data().offset(start as isize), len) }
	}

	/*pub fn names_from_dirent_refs(&mut self, dirent_refs: &[u64]) -> Result<Vec<String>> {
		let compressor = self.compressor()?;
		let meta_reader = self.meta_reader(&compressor, None)?; // TODO Set bounds
		let mut ret = Vec::with_capacity(dirent_refs.len());
		for dirent_ref in dirent_refs {
			let (block, offset) = unpack_meta_ref(*dirent_ref);
			unsafe { sfs_check(sqfs_meta_reader_seek(*meta_reader, block, offset), "Couldn't seek to directory entry")?; }
			let entry = sfs_init_ptr(&|x| unsafe {
				sqfs_meta_reader_read_dir_ent(*meta_reader, x)
			}, "Couldn't read directory entry by reference", libc_free)?;
			let name_bytes = unsafe { (**entry).name.as_slice((**entry).size as usize + 1) };
			ret.push(String::from_utf8(name_bytes.to_vec())?);
		}
		Ok(ret)
	}*/
}

unsafe impl Send for Archive { }
unsafe impl Sync for Archive { }
