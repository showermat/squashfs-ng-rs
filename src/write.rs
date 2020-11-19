use std::cell::RefCell;
use std::collections::{BTreeMap, HashMap};
use std::ffi::{CString, OsString};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, RwLock};
use std::time::SystemTime;
use super::*;
use super::SquashfsError;
use walkdir::{DirEntry, WalkDir};

#[repr(u32)]
pub enum BlockFlags {
	DontCompress = super::SQFS_BLK_FLAGS_SQFS_BLK_DONT_COMPRESS,
	BlockAlign = super::SQFS_BLK_FLAGS_SQFS_BLK_ALIGN,
	DontFragment = super::SQFS_BLK_FLAGS_SQFS_BLK_DONT_FRAGMENT,
	DontDeduplicate = super::SQFS_BLK_FLAGS_SQFS_BLK_DONT_DEDUPLICATE,
	IgnoreSparse = super::SQFS_BLK_FLAGS_SQFS_BLK_IGNORE_SPARSE,
	DontHash = super::SQFS_BLK_FLAGS_SQFS_BLK_DONT_HASH,
}

pub enum SourceData {
	File(Box<dyn Read + Sync + Send>),
	Dir(Box<dyn Iterator<Item=(OsString, u32)> + Sync + Send>),
	Symlink(OsString),
	BlockDev(u32, u32),
	CharDev(u32, u32),
	Fifo,
	Socket,
}

pub struct Source {
	pub data: SourceData,
	pub uid: u32,
	pub gid: u32,
	pub mode: u16,
	pub modified: u32,
	pub xattrs: HashMap<OsString, Vec<u8>>,
	pub flags: u32,
}

fn file_xattrs(path: &Path) -> Result<HashMap<OsString, Vec<u8>>> {
	xattr::list(path)?.map(|attr| {
		let value = xattr::get(path, attr.clone()).map_err(|e| SquashfsError::Xattr(path.to_path_buf(), e))?
			.expect(&format!("Could not retrieve xattr {:?} reported to be present", attr));
		Ok((attr, value))
	}).collect()
}

fn copy_metadata(src: &ManagedPointer<sqfs_inode_generic_t>, dst: &mut ManagedPointer<sqfs_inode_generic_t>) -> Result<()> {
	let (src_base, dst_base) = unsafe { (&(***src).base, &mut (***dst).base) };
	dst_base.mode = src_base.mode;
	dst_base.uid_idx = src_base.uid_idx;
	dst_base.gid_idx = src_base.gid_idx;
	dst_base.mod_time = src_base.mod_time;
	dst_base.inode_number = src_base.inode_number;
	let mut xattr_idx: u32 = 0;
	unsafe {
		sfs_check(sqfs_inode_get_xattr_index(**src, &mut xattr_idx), "Couldn't get xattr index")?;
		sfs_check(sqfs_inode_set_xattr_index(**dst, xattr_idx), "Couldn't set xattr index")?;
	}
	Ok(())
}

impl Source {
	pub fn defaults(data: SourceData) -> Self {
		Self { data: data, uid: 0, gid: 0, mode: 0x1ff, modified: 0, xattrs: HashMap::new(), flags: 0 }
	}

	fn devno(maj: u32, min: u32) -> u32 {
		((min & 0xfff00) << 20) | ((maj & 0xfff) << 8) | (min & 0xff)
	}

	// TODO Handle hard links
	unsafe fn to_inode(&self, link_count: u32) -> Result<ManagedPointer<sqfs_inode_generic_t>> {
		unsafe fn create_inode(kind: SQFS_INODE_TYPE, extra: usize) -> ManagedPointer<sqfs_inode_generic_t> {
			use std::alloc::{alloc, Layout};
			use std::mem::{align_of, size_of};
			let layout = Layout::from_size_align_unchecked(size_of::<sqfs_inode_generic_t>() + extra, align_of::<sqfs_inode_generic_t>());
			let ret = alloc(layout) as *mut sqfs_inode_generic_t;
			(*ret).base.type_ = kind as u16;
			ManagedPointer::new(ret, rust_dealloc)
		}
		let ret = match &self.data {
			SourceData::File(_) => create_inode(SQFS_INODE_TYPE_SQFS_INODE_FILE, 0),
			SourceData::Dir(_) => {
				let mut ret = create_inode(SQFS_INODE_TYPE_SQFS_INODE_DIR, 0);
				(**ret).data.dir.nlink = link_count;
				ret
			},
			SourceData::Symlink(dest_os) => {
				let dest = os_to_string(&dest_os)?.into_bytes();
				let mut ret = create_inode(SQFS_INODE_TYPE_SQFS_INODE_SLINK, dest.len());
				let mut data = &mut (**ret).data.slink;
				data.nlink = link_count;
				data.target_size = dest.len() as u32;
				let dest_field = std::mem::transmute::<_, &mut [u8]>((**ret).extra.as_mut_slice(dest.len()));
				dest_field.copy_from_slice(dest.as_slice());
				ret
			},
			SourceData::BlockDev(maj, min) => {
				let mut ret = create_inode(SQFS_INODE_TYPE_SQFS_INODE_BDEV, 0);
				let mut data = &mut (**ret).data.dev;
				data.nlink = link_count;
				data.devno = Self::devno(*maj, *min);
				ret
			},
			SourceData::CharDev(maj, min) => {
				let mut ret = create_inode(SQFS_INODE_TYPE_SQFS_INODE_CDEV, 0);
				let mut data = &mut (**ret).data.dev;
				data.nlink = link_count;
				data.devno = Self::devno(*maj, *min);
				ret
			},
			SourceData::Fifo => {
				let mut ret = create_inode(SQFS_INODE_TYPE_SQFS_INODE_FIFO, 0);
				(**ret).data.ipc.nlink = link_count;
				ret
			},
			SourceData::Socket => {
				let mut ret = create_inode(SQFS_INODE_TYPE_SQFS_INODE_SOCKET, 0);
				(**ret).data.ipc.nlink = link_count;
				ret
			},
		};
		Ok(ret)
	}
}

struct IntermediateNode {
	inode: Box<ManagedPointer<sqfs_inode_generic_t>>,
	dir_children: Option<Box<dyn Iterator<Item=(OsString, u32)> + Sync + Send>>,
	pos: u64,
}

pub struct SourceFile {
	pub path: PathBuf,
	pub content: Source,
}

pub struct Writer {
	outfile: ManagedPointer<sqfs_file_t>,
	#[allow(dead_code)] compressor_config: sqfs_compressor_config_t, // Referenced by `compressor`
	compressor: ManagedPointer<sqfs_compressor_t>,
	superblock: sqfs_super_t,
	#[allow(dead_code)] block_writer: ManagedPointer<sqfs_block_writer_t>, // Referenced by `block_processor`
	block_processor: Mutex<ManagedPointer<sqfs_block_processor_t>>,
	frag_table: ManagedPointer<sqfs_frag_table_t>,
	id_table: Mutex<ManagedPointer<sqfs_id_table_t>>,
	xattr_writer: Mutex<ManagedPointer<sqfs_xattr_writer_t>>,
	inode_writer: ManagedPointer<sqfs_meta_writer_t>,
	dirent_writer: ManagedPointer<sqfs_meta_writer_t>,
	dir_writer: ManagedPointer<sqfs_dir_writer_t>,
	nodes: Mutex<Vec<RefCell<IntermediateNode>>>,
	finished: RwLock<bool>,
}

impl Writer {
	pub fn open<T: AsRef<Path>>(path: T) -> Result<Self> {
		let cpath = CString::new(os_to_string(path.as_ref().as_os_str())?)?;
		let block_size = SQFS_DEFAULT_BLOCK_SIZE as u64;
		let num_workers = num_cpus::get() as u32;
		let compressor_id = SQFS_COMPRESSOR_SQFS_COMP_ZSTD;
		let now = SystemTime::now().duration_since(SystemTime::UNIX_EPOCH)?.as_secs() as u32;
		let outfile = sfs_init_check_null(&|| unsafe {
			sqfs_open_file(cpath.as_ptr(), SQFS_FILE_OPEN_FLAGS_SQFS_FILE_OPEN_OVERWRITE)
		}, &format!("Couldn't open output file {}", path.as_ref().display()), sfs_destroy)?;
		let compressor_config = sfs_init(&|x| unsafe {
			sqfs_compressor_config_init(x, compressor_id, block_size, 0)
		}, "Couldn't create compressor config")?;
		let compressor = sfs_init_ptr(&|x| unsafe {
			sqfs_compressor_create(&compressor_config, x)
		}, "Couldn't create compressor", sfs_destroy)?;
		let superblock = sfs_init(&|x| unsafe {
			sqfs_super_init(x, block_size, now, compressor_id)
		}, "Couldn't create superblock")?;
		let frag_table = sfs_init_check_null(&|| unsafe {
			sqfs_frag_table_create(0)
		}, "Couldn't create fragment table", sfs_destroy)?;
		let block_writer = sfs_init_check_null(&|| unsafe {
			sqfs_block_writer_create(*outfile, 4096, 0)
		}, "Couldn't create block writer", sfs_destroy)?;
		let block_processor = Mutex::new(sfs_init_check_null(&|| unsafe {
			sqfs_block_processor_create(block_size, *compressor, num_workers, 10 * num_workers as u64, *block_writer, *frag_table)
		}, "Couldn't create block processor", sfs_destroy)?);
		let id_table = Mutex::new(sfs_init_check_null(&|| unsafe {
			sqfs_id_table_create(0)
		}, "Couldn't create ID table", sfs_destroy)?);
		let xattr_writer = Mutex::new(sfs_init_check_null(&|| unsafe {
			sqfs_xattr_writer_create(0)
		}, "Couldn't create xattr writer", sfs_destroy)?);
		let inode_writer = sfs_init_check_null(&|| unsafe {
			sqfs_meta_writer_create(*outfile, *compressor, 0)
		}, "Couldn't create inode metadata writer", sfs_destroy)?;
		let dirent_writer = sfs_init_check_null(&|| unsafe {
			sqfs_meta_writer_create(*outfile, *compressor, SQFS_META_WRITER_FLAGS_SQFS_META_WRITER_KEEP_IN_MEMORY)
		}, "Couldn't create directory entry metadata writer", sfs_destroy)?;
		let dir_writer = sfs_init_check_null(&|| unsafe {
			sqfs_dir_writer_create(*dirent_writer, SQFS_DIR_WRITER_CREATE_FLAGS_SQFS_DIR_WRITER_CREATE_EXPORT_TABLE)
		}, "Couldn't create directory writer", sfs_destroy)?;
		unsafe {
			sfs_check(sqfs_super_write(&superblock, *outfile), "Couldn't write archive superblock")?;
			sfs_check((**compressor).write_options.expect("Compressor doesn't provide write_options")(*compressor, *outfile), "Couldn't write compressor options")?;
		}
		Ok(Self {
			outfile: outfile,
			compressor_config: compressor_config,
			compressor: compressor,
			superblock: superblock,
			block_writer: block_writer,
			block_processor: block_processor,
			frag_table: frag_table,
			id_table: id_table,
			xattr_writer: xattr_writer,
			inode_writer: inode_writer,
			dirent_writer: dirent_writer,
			dir_writer: dir_writer,
			nodes: Mutex::new(vec![]),
			finished: RwLock::new(false),
		})
	}

	fn mode_from_inode(inode: &ManagedPointer<sqfs_inode_generic_t>) -> u16 {
		lazy_static! {
			static ref TYPENUMS: HashMap<u32, u32> = vec![
				(SQFS_INODE_TYPE_SQFS_INODE_DIR, S_IFDIR),
				(SQFS_INODE_TYPE_SQFS_INODE_FILE, S_IFREG),
				(SQFS_INODE_TYPE_SQFS_INODE_SLINK, S_IFLNK),
				(SQFS_INODE_TYPE_SQFS_INODE_BDEV, S_IFBLK),
				(SQFS_INODE_TYPE_SQFS_INODE_CDEV, S_IFCHR),
				(SQFS_INODE_TYPE_SQFS_INODE_FIFO, S_IFIFO),
				(SQFS_INODE_TYPE_SQFS_INODE_SOCKET, S_IFSOCK),
				(SQFS_INODE_TYPE_SQFS_INODE_EXT_DIR, S_IFDIR),
				(SQFS_INODE_TYPE_SQFS_INODE_EXT_FILE, S_IFREG),
				(SQFS_INODE_TYPE_SQFS_INODE_EXT_SLINK, S_IFLNK),
				(SQFS_INODE_TYPE_SQFS_INODE_EXT_BDEV, S_IFBLK),
				(SQFS_INODE_TYPE_SQFS_INODE_EXT_CDEV, S_IFCHR),
				(SQFS_INODE_TYPE_SQFS_INODE_EXT_FIFO, S_IFIFO),
				(SQFS_INODE_TYPE_SQFS_INODE_EXT_SOCKET, S_IFSOCK),
			].into_iter().collect();
		}
		let base = unsafe { (***inode).base };
		TYPENUMS[&(base.type_ as u32)] as u16 | base.mode
	}

	fn outfile_size(&self) -> u64 {
		unsafe { (**self.outfile).get_size.expect("Superblock doesn't provide get_size")(*self.outfile) }
	}

	pub fn add(&mut self, mut source: Source) -> Result<u32> {
		let finished = self.finished.read().expect("Poisoned lock");
		if *finished { Err(SquashfsError::Finished)?; }
		let flags = source.flags;
		let nlink = 1; // TODO Handle hard links
		let mut inode = unsafe {
			match source.data {
				SourceData::File(ref mut reader) => {
					let mut ret = Box::new(ManagedPointer::null(libc_free));
					let block_processor = self.block_processor.lock().expect("Poisoned lock");
					sfs_check(sqfs_block_processor_begin_file(**block_processor, &mut **ret, ptr::null_mut(), flags), "Couldn't begin writing file")?;
					let mut buf = vec![0; BLOCK_BUF_SIZE];
					loop {
						let rdsize = reader.read(&mut buf)? as u64;
						if rdsize == 0 { break; }
						sfs_check(sqfs_block_processor_append(**block_processor, &buf as &[u8] as *const [u8] as *const libc::c_void, rdsize), "Couldn't write file data block")?;
					}
					sfs_check(sqfs_block_processor_end_file(**block_processor), "Couldn't finish writing file")?;
					ret
				},
				_ => Box::new(source.to_inode(nlink)?),
			}
		};
		unsafe {
			let xattr_writer = self.xattr_writer.lock().expect("Poisoned lock");
			sfs_check(sqfs_xattr_writer_begin(**xattr_writer, 0), "Couldn't start writing xattrs")?;
			for (key, value) in &source.xattrs {
				let ckey = CString::new(os_to_string(key)?)?;
				sfs_check(sqfs_xattr_writer_add(**xattr_writer, ckey.as_ptr() as *const i8, value.as_ptr() as *const libc::c_void, value.len() as u64), "Couldn't add xattr")?;
			}
			let xattr_idx = sfs_init(&|x| sqfs_xattr_writer_end(**xattr_writer, x), "Couldn't finish writing xattrs")?;
			let mut base = &mut (***inode).base;
			base.mode = source.mode;
			sqfs_inode_set_xattr_index(**inode, xattr_idx);
			let id_table = self.id_table.lock().expect("Poisoned lock");
			sfs_check(sqfs_id_table_id_to_index(**id_table, source.uid, &mut base.uid_idx), "Couldn't set inode UID")?;
			sfs_check(sqfs_id_table_id_to_index(**id_table, source.gid, &mut base.gid_idx), "Couldn't set inode GID")?;
			base.mod_time = source.modified;
		}
		let dir_children = match source.data {
			SourceData::Dir(children) => Some(children),
			_ => None,
		};
		let mut nodes = self.nodes.lock().expect("Poisoned lock");
		unsafe { (***inode).base.inode_number = nodes.len() as u32 + 1; }
		nodes.push(RefCell::new(IntermediateNode { inode: inode, dir_children: dir_children, pos: 0 }));
		Ok(nodes.len() as u32)
	}

	pub fn finish(&mut self) -> Result<()> {
		*self.finished.write().expect("Poisoned lock") = true;
		let nodes = self.nodes.lock().expect("Poisoned lock");
		unsafe {
			sfs_check(sqfs_block_processor_finish(**self.block_processor.lock().expect("Poisoned lock")), "Failed finishing block processing")?;
			self.superblock.inode_table_start = self.outfile_size();
			for raw_node in &*nodes {
				let mut node = raw_node.borrow_mut();
				let id = (***node.inode).base.inode_number;
				if let Some(children) = node.dir_children.take() {
					sfs_check(sqfs_dir_writer_begin(*self.dir_writer, 0), "Couldn't start writing directory")?;
					// For each child, need: name, ID, reference, mode
					for (name, child_id) in children { // On disk children need to be sorted -- I think the library takes care of this
						if child_id >= id { Err(SquashfsError::WriteOrder(id, child_id))?; }
						let child_node = &nodes[child_id as usize - 1].borrow();
						let child = child_node.inode.as_ref();
						let child_ref = child_node.pos;
						sfs_check(sqfs_dir_writer_add_entry(*self.dir_writer, CString::new(os_to_string(&name)?)?.as_ptr(), child_id, child_ref, Self::mode_from_inode(&child)), "Couldn't add directory entry")?;
					}
					sfs_check(sqfs_dir_writer_end(*self.dir_writer), "Couldn't finish writing directory")?;
					let mut ret = Box::new(sfs_init_check_null(&|| {
						sqfs_dir_writer_create_inode(*self.dir_writer, 0, 0, 0) // TODO Populate the parent inode number (how?)
					}, "Couldn't get inode for directory", libc_free)?);
					copy_metadata(&*node.inode, &mut ret)?;
					node.inode = ret;
				}
				let (mut block, mut offset) = (0, 0);
				sqfs_meta_writer_get_position(*self.inode_writer, &mut block, &mut offset);
				node.pos = block << 16 | offset as u64;
				sfs_check(sqfs_meta_writer_write_inode(*self.inode_writer, **node.inode), "Couldn't write inode")?;
			}

			let root_ref = nodes.last().ok_or(SquashfsError::Empty)?.borrow().pos;
			self.superblock.root_inode_ref = root_ref;
			sfs_check(sqfs_meta_writer_flush(*self.inode_writer), "Couldn't flush inodes")?;
			sfs_check(sqfs_meta_writer_flush(*self.dirent_writer), "Couldn't flush directory entries")?;
			self.superblock.directory_table_start = self.outfile_size();
			sfs_check(sqfs_meta_write_write_to_file(*self.dirent_writer), "Couldn't write directory entries")?;
			self.superblock.inode_count = nodes.len() as u32;
			sfs_check(sqfs_frag_table_write(*self.frag_table, *self.outfile, &mut self.superblock, *self.compressor), "Couldn't write fragment table")?;
			sfs_check(sqfs_dir_writer_write_export_table(*self.dir_writer, *self.outfile, *self.compressor, nodes.len() as u32, root_ref, &mut self.superblock), "Couldn't write export table")?;
			sfs_check(sqfs_id_table_write(**self.id_table.lock().expect("Poisoned lock"), *self.outfile, &mut self.superblock, *self.compressor), "Couldn't write ID table")?;
			sfs_check(sqfs_xattr_writer_flush(**self.xattr_writer.lock().expect("Poisoned lock"), *self.outfile, &mut self.superblock, *self.compressor), "Couldn't write xattr table")?;
			self.superblock.bytes_used = self.outfile_size();
			sfs_check(sqfs_super_write(&self.superblock, *self.outfile), "Couldn't rewrite archive superblock")?;
			let padding: Vec<u8> = vec![0; PAD_TO - self.outfile_size() as usize % PAD_TO];
			sfs_check((**self.outfile).write_at.expect("File does not provide write_at")(*self.outfile, self.outfile_size(), &padding as &[u8] as *const [u8] as *const libc::c_void, padding.len() as u64), "Couldn't pad file")?;
		}
		Ok(())
	}
}

unsafe impl Sync for Writer { }
unsafe impl Send for Writer { }

pub struct TreeProcessor {
	root: PathBuf,
	writer: Mutex<Writer>,
	childmap: Mutex<HashMap<PathBuf, BTreeMap<OsString, u32>>>,
}

impl TreeProcessor {
	pub fn new<P: AsRef<Path>>(writer: Writer, root: P) -> Result<Self> {
		Ok(Self { root: root.as_ref().to_path_buf(), writer: Mutex::new(writer), childmap: Mutex::new(HashMap::new()) })
	}

	pub fn add(&self, mut source: SourceFile) -> Result<u32> {
		let mut childmap = self.childmap.lock().expect("Poisoned lock");
		if let SourceData::Dir(children) = &mut source.content.data {
			// Pull in any last-minute additions made by the user
			let mut new_children = childmap.remove(&source.path).unwrap_or(BTreeMap::new());
			new_children.extend(children);
			source.content.data = SourceData::Dir(Box::new(new_children.into_iter()));
		}
		let id = self.writer.lock().expect("Poisoned lock").add(source.content)?;
		if let Some(parent) = source.path.parent() {
			childmap.entry(parent.to_path_buf()).or_insert(BTreeMap::new()).insert(source.path.file_name().expect("Path from walkdir has no file name").to_os_string(), id);
		}
		Ok(id)
	}

	pub fn finish(&self) -> Result<()> {
		self.writer.lock().expect("Poisoned lock").finish()
	}

	fn make_source(&self, entry: DirEntry) -> Result<Source> {
		let metadata = entry.metadata().unwrap();
		let mtime = metadata.modified()?.duration_since(SystemTime::UNIX_EPOCH)?.as_secs() as u32;
		let data = if metadata.file_type().is_dir() {
			SourceData::Dir(Box::new(self.childmap.lock().expect("Poisoned lock").remove(&entry.path().to_path_buf()).unwrap_or(BTreeMap::new()).into_iter()))
		}
		else if metadata.file_type().is_file() {
			SourceData::File(Box::new(std::fs::File::open(entry.path())?))
		}
		else if metadata.file_type().is_symlink() {
			SourceData::Symlink(std::fs::read_link(entry.path())?.into_os_string())
		}
		else {
			Err(SquashfsError::WriteType(metadata.file_type()))?;
			unreachable!();
		};
		let source = if cfg!(linux) {
			use std::os::linux::fs::MetadataExt;
			Source { data: data, xattrs: file_xattrs(entry.path())?, uid: metadata.st_uid(), gid: metadata.st_gid(), mode: (metadata.st_mode() & !S_IFMT) as u16, modified: mtime, flags: 0 }
		}
		else if cfg!(unix) {
			use std::os::unix::fs::MetadataExt;
			Source { data: data, xattrs: HashMap::new(), uid: metadata.uid(), gid: metadata.gid(), mode: (metadata.mode() & 0x1ff) as u16, modified: mtime, flags: 0 }
		}
		else {
			Source { data: data, xattrs: HashMap::new(), uid: 0, gid: 0, mode: 0x1ff, modified: mtime, flags: 0 }
		};
		Ok(source)
	}

	pub fn iter<'a>(&'a self) -> TreeIterator<'a> {
		let tree = WalkDir::new(&self.root).follow_links(false).contents_first(true);
		TreeIterator { processor: self, tree: tree.into_iter() }
	}
}

pub struct TreeIterator<'a> {
	processor: &'a TreeProcessor,
	tree: walkdir::IntoIter,
}

impl<'a> std::iter::Iterator for TreeIterator<'a> {
	type Item = Result<SourceFile>;

	fn next(&mut self) -> Option<Self::Item> {
		match self.tree.next() {
			None => None,
			Some(Ok(entry)) => {
				let path = entry.path().to_path_buf();
				Some(self.processor.make_source(entry).map(|source| SourceFile { path: path, content: source }))
			}
			Some(Err(e)) => {
				let path = e.path().map(|x| x.to_string_lossy().into_owned()).unwrap_or("(unknown)".to_string());
				eprintln!("Not processing {}: {}", path, e.to_string());
				self.next()
			}
		}
	}
}
