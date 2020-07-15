use std::cell::RefCell;
use std::collections::{BTreeMap, HashMap};
use std::ffi::{CStr, CString, OsStr, OsString};
use std::io::Read;
use std::path::Path;
use std::time::SystemTime;
use bindings::*;
use super::*;
use super::SquashfsError;
use thiserror::Error;
use walkdir::{DirEntry, WalkDir};

pub mod BlockFlags {
	pub const DontCompress: u32 = super::SQFS_BLK_FLAGS_SQFS_BLK_DONT_COMPRESS;
	pub const BlockAlign: u32 = super::SQFS_BLK_FLAGS_SQFS_BLK_ALIGN;
	pub const DontFragment: u32 = super::SQFS_BLK_FLAGS_SQFS_BLK_DONT_FRAGMENT;
	pub const DontDeduplicate: u32 = super::SQFS_BLK_FLAGS_SQFS_BLK_DONT_DEDUPLICATE;
	pub const IgnoreSparse: u32 = super::SQFS_BLK_FLAGS_SQFS_BLK_IGNORE_SPARSE;
	pub const DontHash: u32 = super::SQFS_BLK_FLAGS_SQFS_BLK_DONT_HASH;
}

pub enum SourceData {
	File(Box<dyn Read>),
	Dir(Box<dyn Iterator<Item=(OsString, u32)>>),
	Symlink(OsString),
	BlockDev(u32, u32),
	CharDev(u32, u32),
	Fifo,
	Socket,
}

pub struct Source {
	data: SourceData,
	xattrs: HashMap<OsString, Vec<u8>>,
	uid: u32,
	gid: u32,
	mode: u16,
	modified: u32,
	flags: u32,
}

fn copy_metadata(src: &ManagedPointer<sqfs_inode_generic_t>, dst: &mut ManagedPointer<sqfs_inode_generic_t>) {
	fn nlink_ref(inode: &ManagedPointer<sqfs_inode_generic_t>) -> Option<&u32> {
		unimplemented!();
	}
	let (src_base, dst_base) = unsafe { (&(***src).base, &mut (***dst).base) };
	dst_base.mode = src_base.mode;
	dst_base.uid_idx = src_base.uid_idx;
	dst_base.gid_idx = src_base.gid_idx;
	dst_base.mod_time = src_base.mod_time;
	dst_base.inode_number = src_base.inode_number;
	// TODO xattr_idx, uid, git, mode, mtime, link_count
}

impl Source {
	pub fn new(data: SourceData, xattrs: HashMap<OsString, Vec<u8>>, parent: u32, flags: u32) -> Self { // TODO Parent not necessary?
		Self { data: data, xattrs: xattrs, uid: 1000, gid: 1001, mode: 0x1ff, modified: 0, flags: flags }
	}

	fn devno(maj: u32, min: u32) -> u32 {
		((min & 0xfff00) << 20) | ((maj & 0xfff) << 8) | (min & 0xff)
	}

	// TODO Handle hard links
	fn to_inode(&self, link_count: u32) -> Result<ManagedPointer<sqfs_inode_generic_t>> {
		fn create_inode(kind: SQFS_INODE_TYPE, extra: usize) -> ManagedPointer<sqfs_inode_generic_t> {
			use std::alloc::{alloc, Layout};
			use std::mem::{align_of, size_of};
			unsafe {
				let layout = Layout::from_size_align_unchecked(size_of::<sqfs_inode_generic_t>() + extra, align_of::<sqfs_inode_generic_t>());
				let ret = alloc(layout) as *mut sqfs_inode_generic_t;
				(*ret).base.type_ = kind as u16;
				ManagedPointer::new(ret, rust_dealloc)
			}
		}
		let ret = unsafe {
			match &self.data {
				SourceData::File(_) => {
					let mut ret = create_inode(SQFS_INODE_TYPE_SQFS_INODE_FILE, 0);
					ret
				},
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
			}
		};
		Ok(ret)
	}
}

struct IntermediateNode {
	inode: Box<ManagedPointer<sqfs_inode_generic_t>>,
	dir_children: Option<Box<dyn Iterator<Item=(OsString, u32)>>>,
	pos: u64,
	parent: u32, // TODO Calculate rather than requiring
}

pub struct Writer {
	outfile: ManagedPointer<sqfs_file_t>,
	compressor_config: sqfs_compressor_config_t,
	compressor: ManagedPointer<sqfs_compressor_t>,
	superblock: sqfs_super_t,
	block_writer: ManagedPointer<sqfs_block_writer_t>,
	block_processor: ManagedPointer<sqfs_block_processor_t>,
	frag_table: ManagedPointer<sqfs_frag_table_t>,
	id_table: ManagedPointer<sqfs_id_table_t>,
	xattr_writer: ManagedPointer<sqfs_xattr_writer_t>,
	inode_writer: ManagedPointer<sqfs_meta_writer_t>,
	dirent_writer: ManagedPointer<sqfs_meta_writer_t>,
	dir_writer: ManagedPointer<sqfs_dir_writer_t>,
	nodes: Vec<RefCell<IntermediateNode>>,
}

impl Writer {
	pub fn open(path: &Path) -> Result<Self> {
		let cpath = CString::new(os_to_string(path.as_os_str())?)?;
		let block_size = SQFS_DEFAULT_BLOCK_SIZE as u64;
		let num_workers = 1;
		let compressor_id = SQFS_COMPRESSOR_SQFS_COMP_ZSTD;
		let now = 0; // TODO Get current timestamp
		let outfile = ManagedPointer::new(sfs_init_check_null(&|| unsafe {
			sqfs_open_file(cpath.as_ptr(), SQFS_FILE_OPEN_FLAGS_SQFS_FILE_OPEN_OVERWRITE)
		}, &format!("Couldn't open output file {}", path.display()))?, sfs_destroy);
		let compressor_config = sfs_init(&|x| unsafe {
			sqfs_compressor_config_init(x, compressor_id, block_size, 0)
		}, "Couldn't create compressor config")?;
		let compressor = ManagedPointer::new(sfs_init_ptr(&|x| unsafe {
			sqfs_compressor_create(&compressor_config, x)
		}, "Couldn't create compressor")?, sfs_destroy);
		let superblock = sfs_init(&|x| unsafe {
			sqfs_super_init(x, block_size, now, compressor_id)
		}, "Couldn't create superblock")?;
		let frag_table = ManagedPointer::new(sfs_init_check_null(&|| unsafe {
			sqfs_frag_table_create(0)
		}, "Couldn't create fragment table")?, sfs_destroy);
		let block_writer = ManagedPointer::new(sfs_init_check_null(&|| unsafe {
			sqfs_block_writer_create(*outfile, 4096, 0)
		}, "Couldn't create block writer")?, sfs_destroy);
		let block_processor = ManagedPointer::new(sfs_init_check_null(&|| unsafe {
			sqfs_block_processor_create(block_size, *compressor, num_workers, 10 * num_workers as u64, *block_writer, *frag_table)
		}, "Couldn't create block processor")?, sfs_destroy);
		let id_table = ManagedPointer::new(sfs_init_check_null(&|| unsafe {
			sqfs_id_table_create(0)
		}, "Couldn't create ID table")?, sfs_destroy);
		let xattr_writer = ManagedPointer::new(sfs_init_check_null(&|| unsafe {
			sqfs_xattr_writer_create(0)
		}, "Couldn't create xattr writer")?, sfs_destroy);
		let inode_writer = ManagedPointer::new(sfs_init_check_null(&|| unsafe {
			sqfs_meta_writer_create(*outfile, *compressor, 0)
		}, "Couldn't create inode metadata writer")?, sfs_destroy);
		let dirent_writer = ManagedPointer::new(sfs_init_check_null(&|| unsafe {
			sqfs_meta_writer_create(*outfile, *compressor, SQFS_META_WRITER_FLAGS_SQFS_META_WRITER_KEEP_IN_MEMORY) // TODO Untangle so we don't have to keep in memory
		}, "Couldn't create directory entry metadata writer")?, sfs_destroy);
		let dir_writer = ManagedPointer::new(sfs_init_check_null(&|| unsafe {
			sqfs_dir_writer_create(*dirent_writer, SQFS_DIR_WRITER_CREATE_FLAGS_SQFS_DIR_WRITER_CREATE_EXPORT_TABLE)
		}, "Couldn't create directory writer")?, sfs_destroy);
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
			nodes: vec![],
		})
	}

	fn mode_from_inode(inode: &ManagedPointer<sqfs_inode_generic_t>) -> u16 {
		let typenums = vec![ // TODO Lazy static
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
		].into_iter().collect::<HashMap<u32, u32>>();
		let base = unsafe { (***inode).base };
		typenums[&(base.type_ as u32)] as u16 | base.mode
	}

	fn outfile_size(&self) -> u64 {
		unsafe { (**self.outfile).get_size.expect("Superblock doesn't provide get_size")(*self.outfile) }
	}

	// TODO Minimize unsafe blocks
	pub fn add(&mut self, mut source: Source) -> Result<u32> {
		let flags = source.flags;
		let nlink = 1; // TODO Handle hard links
		let mut inode = match source.data {
			SourceData::File(ref mut reader) => {
				let mut ret = Box::new(ManagedPointer::null(libc_free));
				unsafe {
					sfs_check(sqfs_block_processor_begin_file(*self.block_processor, &mut **ret, ptr::null_mut(), flags), "Couldn't begin writing file")?;
					let mut buf = vec![0; BLOCK_BUF_SIZE];
					loop {
						let rdsize = reader.read(&mut buf)? as u64;
						if rdsize == 0 { break; }
						sfs_check(sqfs_block_processor_append(*self.block_processor, &buf as &[u8] as *const [u8] as *const libc::c_void, rdsize), "Couldn't write file data block")?;
					}
					sfs_check(sqfs_block_processor_end_file(*self.block_processor), "Couldn't finish writing file")?;
				}
				ret
			},
			_ => Box::new(source.to_inode(nlink)?),
		};
		unsafe {
			sfs_check(sqfs_xattr_writer_begin(*self.xattr_writer, 0), "Couldn't start writing xattrs")?;
			for (key, value) in &source.xattrs {
				let ckey = CString::new(os_to_string(key)?)?;
				sfs_check(sqfs_xattr_writer_add(*self.xattr_writer, ckey.as_ptr() as *const i8, value as &[u8] as *const [u8] as *const libc::c_void, value.len() as u64), "Couldn't add xattr")?;
			}
			let xattr_idx = unsafe { sfs_init(&|x| sqfs_xattr_writer_end(*self.xattr_writer, x), "Couldn't finish writing xattrs")? };
			let mut base = &mut (***inode).base;
			base.mode = source.mode;
			sqfs_inode_set_xattr_index(**inode, xattr_idx);
			sfs_check(sqfs_id_table_id_to_index(*self.id_table, source.uid, &mut base.uid_idx), "Couldn't set inode UID");
			sfs_check(sqfs_id_table_id_to_index(*self.id_table, source.gid, &mut base.gid_idx), "Couldn't set inode GID");
			base.mod_time = source.modified;
			base.inode_number = self.nodes.len() as u32 + 1;;
		}
		let dir_children = match source.data {
			SourceData::Dir(children) => Some(children),
			_ => None,
		};
		self.nodes.push(RefCell::new(IntermediateNode { inode: inode, dir_children: dir_children, pos: 0, parent: 0 }));
		Ok(self.nodes.len() as u32)
	}

	pub fn finish(&mut self) -> Result<()> {
		unsafe {
			sfs_check(sqfs_block_processor_finish(*self.block_processor), "Failed finishing block processing")?;
			self.superblock.inode_table_start = self.outfile_size();
			for raw_node in &self.nodes {
				let mut node = raw_node.borrow_mut();
				// TODO Handle extended inodes properly
				// TODO What happens if a dir tries to include itself as a child?  Probably a RefCell borrow panic.
				let id = (***node.inode).base.inode_number;
				if let Some(children) = node.dir_children.take() {
					sfs_check(sqfs_dir_writer_begin(*self.dir_writer, 0), "Couldn't start writing directory")?;
					// For each child, need: name, ID, reference, mode
					for (name, child_id) in children { // TODO Check that children are sorted
						if child_id >= id { panic!("Tried to write directory {} before child {}", id, child_id) } // TODO Allocate error
						let child_node = &self.nodes[child_id as usize - 1].borrow();
						let child = child_node.inode.as_ref();
						let child_ref = child_node.pos;
						sfs_check(sqfs_dir_writer_add_entry(*self.dir_writer, CString::new(os_to_string(&name)?)?.as_ptr(), child_id, child_ref, Self::mode_from_inode(&child)), "Couldn't add directory entry")?;
					}
					sfs_check(sqfs_dir_writer_end(*self.dir_writer), "Couldn't finish writing directory")?;
					let mut ret = Box::new(ManagedPointer::new(sfs_init_check_null(&|| sqfs_dir_writer_create_inode(*self.dir_writer, 0, 0, node.parent), "Couldn't get inode for directory")?, libc_free));
					copy_metadata(&*node.inode, &mut ret);
					node.inode = ret;
				}
				let (mut block, mut offset) = (0, 0);
				sqfs_meta_writer_get_position(*self.inode_writer, &mut block, &mut offset);
				node.pos = block << 16 | offset as u64;
				sfs_check(sqfs_meta_writer_write_inode(*self.inode_writer, **node.inode), "Couldn't write inode")?;
			}

			let root_ref = self.nodes.last().ok_or(SquashfsError::Empty)?.borrow().pos;
			self.superblock.root_inode_ref = root_ref;
			sfs_check(sqfs_meta_writer_flush(*self.inode_writer), "Couldn't flush inodes")?;
			sfs_check(sqfs_meta_writer_flush(*self.dirent_writer), "Couldn't flush directory entries")?;
			self.superblock.directory_table_start = self.outfile_size();
			sfs_check(sqfs_meta_write_write_to_file(*self.dirent_writer), "Couldn't write directory entries")?;
			(self.superblock).inode_count = self.nodes.len() as u32;
			sfs_check(sqfs_frag_table_write(*self.frag_table, *self.outfile, &mut self.superblock, *self.compressor), "Couldn't write fragment table")?;
			sfs_check(sqfs_dir_writer_write_export_table(*self.dir_writer, *self.outfile, *self.compressor, self.nodes.len() as u32, root_ref, &mut self.superblock), "Couldn't write export table")?;
			sfs_check(sqfs_id_table_write(*self.id_table, *self.outfile, &mut self.superblock, *self.compressor), "Couldn't write ID table")?;
			sfs_check(sqfs_xattr_writer_flush(*self.xattr_writer, *self.outfile, &mut self.superblock, *self.compressor), "Couldn't write xattr table")?;
			self.superblock.bytes_used = self.outfile_size();
			self.superblock.modification_time = SystemTime::now().duration_since(SystemTime::UNIX_EPOCH)?.as_secs() as u32;
			sfs_check(sqfs_super_write(&self.superblock, *self.outfile), "Couldn't rewrite archive superblock")?;
			let padding: Vec<u8> = vec![0; PAD_TO - self.outfile_size() as usize % PAD_TO];
			sfs_check((**self.outfile).write_at.expect("File does not provide write_at")(*self.outfile, self.outfile_size(), &padding as &[u8] as *const [u8] as *const libc::c_void, padding.len() as u64), "Couldn't pad file");
		}
		Ok(())
	}

	pub fn add_tree<T: AsRef<Path>>(&mut self, root: T, callback: &Fn(Source) -> Result<Source>) -> Result<()> {
		let mut childmap: HashMap<PathBuf, BTreeMap<OsString, u32>> = HashMap::new();
		for step in WalkDir::new(root.as_ref()).follow_links(false).contents_first(true) {
			match step {
				Ok(entry) => {
					// TODO Consider adding Unix-specific functionality with graceful degradation
					// TODO Catch all errors except add() and continue
					let metadata = entry.metadata().unwrap();
					let mtime = metadata.modified()?.duration_since(SystemTime::UNIX_EPOCH)?.as_secs() as u32;
					let data = if metadata.file_type().is_dir() {
						SourceData::Dir(Box::new(childmap.remove(&entry.path().to_path_buf()).unwrap_or(BTreeMap::new()).into_iter()))
					}
					else if metadata.file_type().is_file() {
						SourceData::File(Box::new(std::fs::File::open(entry.path())?))
					}
					else if metadata.file_type().is_symlink() {
						SourceData::Symlink(std::fs::read_link(entry.path())?.into_os_string())
					}
					else {
						panic!("Unknown or unsupported file type"); // TODO Error
					};
					let id = self.add(callback(Source { data: data, xattrs: HashMap::new(), uid: 0, gid: 0, mode: 0x1ff, modified: mtime, flags: 0 })?)?;
					if let Some(parent) = entry.path().parent() {
						childmap.entry(parent.to_path_buf()).or_insert(BTreeMap::new()).insert(entry.file_name().to_os_string(), id);
					}
					println!("{}: {}", id, entry.path().display());
				},
				Err(e) => {
					let path = e.path().map(|x| x.to_string_lossy().into_owned()).unwrap_or("(unknown)".to_string());
					eprintln!("Not processing {}: {}", path, e.to_string());
				}
			}
		}
		Ok(())
	}
}