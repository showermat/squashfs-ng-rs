//! Facilities for writing SquashFS archives.
//!
//! The most straightforward way to write a SquashFS file from a directory tree on-disk is to use a
//! [`TreeProcessor`].  This provides the ability to make "last-minute" modifications to the files
//! that are added, such as skipping certain files or modifying metadata.
//!
//! To create a totally "synthetic" SquashFS file that is not built from files in a filesystem,
//! open a [`Writer`] and feed [`Source`]s to it.
//!
//! # Limitations
//!
//! This library does not yet handle hard links; files with multiple hard links will be archived as
//! separate files with identical contents (which should be deduplicated and end up taking up
//! little additional space).
//!
//! The SquashFS specification includes a field in directory inodes for the parent inode number,
//! presumably to make `..` directory entries work.  This is one factor that makes it impossible to
//! build a SquashFS file without building out the entire directory tree to be archived in memory.
//! I have tried as hard as poassible to reduce the amount of data that must be stored for each
//! node added, and this architecture makes it infeasible to store parent inodes in directory
//! entries.  I hope to fix this some day, and in the meantime it has not caused problems in the
//! ways I have used the resultant files.

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

/// Flags to fine-tune how an entry is added to the archive.
///
/// These valued can be ORed together and passed in the [`flags`](Source::flags) field of a
/// [`Source`] object.
#[repr(u32)]
pub enum BlockFlags {
	/// Don't compress file data.
	///
	/// By default, files are compressed, and the compressed version is stored in the archive if it
	/// is smaller than the uncompressed version.  Setting this flag will force the file to be
	/// stored uncompressed.
	DontCompress = super::SQFS_BLK_FLAGS_SQFS_BLK_DONT_COMPRESS,

	/// Align the file data to device blocks.
	///
	/// If set, padding will be added before and after this file's data blocks so that it is
	/// aligned to the blocks of the underlying disk.
	BlockAlign = super::SQFS_BLK_FLAGS_SQFS_BLK_ALIGN,

	/// Store the tail of the file in a regular data block rather than a fragment block.
	///
	/// The compressed content of a file to be written to an archive is split into equally-sized
	/// blocks and stored as "data blocks".  The final chunk is usually smaller than the rest, so
	/// these final chunks are collected from multiple files are collected and stored together in
	/// separate "fragment blocks" as an optimization.  If there is a reason for the entire file's
	/// contents to be stored together, fragmentation can be disabled using this flag.
	DontFragment = super::SQFS_BLK_FLAGS_SQFS_BLK_DONT_FRAGMENT,

	/// Don't deduplicated data blocks for this file.
	///
	/// If two files contain an identical data block, the block will be stored only once and both
	/// files' block indices will point to this single block.  The user can force all blocks of a
	/// file to be stored by setting this flag.
	DontDeduplicate = super::SQFS_BLK_FLAGS_SQFS_BLK_DONT_DEDUPLICATE,

	/// Don't elide sparse blocks.
	///
	/// If a block of a file contains only zeros, it will not be stored at all and the file's block
	/// index will mark that the block is all-zero.  This behavior can be disabled so that a zero
	/// block will be written by setting this flag.
	IgnoreSparse = super::SQFS_BLK_FLAGS_SQFS_BLK_IGNORE_SPARSE,

	/// Don't compute block checksums for this file.
	///
	/// Each data block is checksummed to verify data integrity unless this flag is set.
	DontHash = super::SQFS_BLK_FLAGS_SQFS_BLK_DONT_HASH,
}

/// Represents the data of a filesystem object that can be added to an archive.
///
/// When creating the archive, this object is read from a [`Source`] (which additionally describes
/// the filesystem attributes of the node) and used to set the type and contents of the node.
pub enum SourceData {
	/// Create a file with the provided contents.
	///
	/// The contained object will be read and its contents placed in the file written to the
	/// archive.
	File(Box<dyn Read + Sync + Send>),

	/// Create a directory with the given chidren.
	///
	/// The creator must provide an iterator over [`OsString`] and `u32`, which respectively
	/// represent the name and inode number of each child of this directory.  This is one of the
	/// hardest parts about writing archive contents -- all children of each directory must be
	/// written before the directory itself, so that the inode numbers of the children are known.
	/// [`TreeProcessor`] facilitates this by performing a post-order traversal of a filesystem,
	/// ensuring that files are written in the correct order.
	Dir(Box<dyn Iterator<Item=(OsString, u32)> + Sync + Send>),

	/// Create a symbolic link to the given path.
	///
	/// It is not required for the target of the symlink to exist.
	Symlink(PathBuf),

	/// Create a block device file with the given major and minor device numbers.
	BlockDev(u32, u32),

	/// Create a character device file with the given major and minor device numbers.
	CharDev(u32, u32),

	/// Create a named pipe.
	Fifo,

	/// Create a socket.
	Socket,
}

/// A single node to be added to the SquashFS archive.
///
/// This contains a [`SourceData`] instance containing the actual data of the node, along with
/// metadata such as permissions and extended attributes.  The path to the node is not part of this
/// object, because all information necessary to reconstruct the directory tree is contained in the
/// directory iterators.  However, for higher-level mechanisms that abstract away details such as
/// inode numbers, it is helpful to associate a path with each `Source`; [`SourceFile`] is used for
/// this purpose.
///
/// This object is designed to be constructed by the user by setting all fields to the appropriate
/// values.
pub struct Source {
	/// The type of the node and the data it contains.
	pub data: SourceData,

	/// The UID of the file.
	pub uid: u32,

	/// The GID of the file.
	pub gid: u32,

	/// The file mode.
	pub mode: u16,

	/// The modification time of the file as a Unix timestamp.
	pub modified: u32,

	/// Extended attributes on the node.  Each one must start with a valid xattr namespace (such as
	/// "user.", and the values can be arbitrary byte strings.
	pub xattrs: HashMap<OsString, Vec<u8>>,

	/// [`BlockFlags`] to set on the node to control how its contents are archived.  Multiple flags
	/// can be combined using `|`.
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
	/// Construct a `Source` from a `SourceData`, using defaults for all metadata fields.
	pub fn defaults(data: SourceData) -> Self {
		Self { data: data, uid: 0, gid: 0, mode: 0x1ff, modified: 0, xattrs: HashMap::new(), flags: 0 }
	}

	fn devno(maj: u32, min: u32) -> u32 {
		((min & 0xfff00) << 20) | ((maj & 0xfff) << 8) | (min & 0xff)
	}

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
				let dest = os_to_string(dest_os.as_os_str())?.into_bytes();
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

/// A [`Source`] bundled with the path where it should be located.
///
/// While the path of a `Source` is not strictly necessary to build the directory tree, it is a
/// useful way for automatic archive builders like [`TreeProcessor`] to keep track of files as they
/// are being added.
///
/// For purposes for which the metadata stored in [`Source`], like permissions and xattrs, are
/// unnecessary, [`defaults`](Self::defaults) can be used to conveniently construct a `FileSource`
/// from a [`PathBuf`] and [`SourceData`].
pub struct SourceFile {
	pub path: PathBuf,
	pub content: Source,
}

impl SourceFile {
	/// Wrap a `SourceData` in a new `Source`, using defaults for all metadata fields.
	///
	/// This sets UID and GID to 0 and permissions to 0o777, gives a null modification time and no
	/// xattrs, and sets no flags.
	pub fn defaults(path: PathBuf, data: SourceData) -> Self {
		Self { path: path, content: Source::defaults(data) }
	}
}

/// A basic SquashFS writer.
///
/// This provides a simple interface for writing archives.  The user calls [`open`](Self::open),
/// [`add`](Self::add) to add each node, and [`finish`](Self::finish) to finish writing.  This is
/// intended for writing archives that are generated by code or otherwise not reflected by files in
/// a file system -- if you want to archive a tree of files from disk, [`TreeProcessor`] handles
/// directory tracking so that you don't have to do it yourself.
///
/// **Each node must be written before its parent**, and an error will be raised if this invariant
/// is not maintained -- however, this is not detected until `finish` is called.
///
///     let writer = Writer::open("archive.sfs")?;
///     let mut ids = HashMap::new();
///     for i in 0..5 {
///         let mut content = format!("This is the content of file {}.txt.", i).as_bytes();
///         let source = Source::defaults(SourceData::File(Box::new(content)));
///         let id = writer.add(source)?;
///         ids.insert(OsString::from(format!("{}.txt", i)), id);
///     }
///     writer.add(Source::defaults(SourceData::Dir(Box::new(ids.into_iter()))))?;
///     writer.finish()?;
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
	/// Open a new output file for writing.
	///
	/// If the file exists, it will be overwritten.
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

	/// Add the provided `Source` to the archive.
	///
	/// This writes file data and xattrs to the archive directly, while storing directory tree
	/// information to write when `finish` is called.
	///
	/// The returned value is the inode number of the added `Source`.  If the file is to be added
	/// to a directory (that is, almost always), this number needs to be stored so that it can be
	/// provided when the directory is added.  In the current implementation, inode numbers start
	/// at 1 for the first file and count steadily upward, but this behavior may change without
	/// warning.
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
		let nodenum = nodes.len() as u32 + 1;
		unsafe { (***inode).base.inode_number = nodenum; }
		nodes.push(RefCell::new(IntermediateNode { inode: inode, dir_children: dir_children, pos: 0 }));
		Ok(nodenum)
	}

	/// Finish writing the archive and flush all contents to disk.
	///
	/// It is an error to call `add` after this has been run.
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
						if child_id >= id { Err(SquashfsError::WriteOrder(child_id))?; }
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

enum ChildMapEntry {
	Accumulating(BTreeMap<OsString, u32>),
	Done,
}

impl ChildMapEntry {
	fn new() -> Self {
		Self::Accumulating(BTreeMap::new())
	}

	fn add(&mut self, name: OsString, id: u32) -> Result<()> {
		match self {
			Self::Done => Err(SquashfsError::WriteOrder(id))?,
			Self::Accumulating(children) => {
				children.insert(name, id);
				Ok(())
			},
		}
	}

	fn finish(&mut self) -> Result<BTreeMap<OsString, u32>> {
		match std::mem::replace(self, Self::Done) {
			Self::Done => Err(SquashfsError::Internal("Tried to finish directory in tree processor multiple times".to_string()))?,
			Self::Accumulating(children) => Ok(children),
		}
	}
}

/// Tool to help create an archive from a directory in the filesystem.
///
/// This wraps a [`Writer`] and takes care of tracking the directory hierarchy as files are added,
/// populating the iterators of [`SourceData::Dir`]s as necessary.
///
/// To simply create a SquashFS file from a chosen directory, call [`process`](Self::process):
///
///     TreeProcessor::new("archive.sfs")?.process("/home/me/test")?;
///
/// For more control over the addition process -- for example, to exclude certain files, add
/// extended attributes, ignore errors, or print files as they are added -- use
/// [`iter`](Self::iter) to get an iterator over the directory tree, and then call
/// [`add`](Self::add) on each `SourceFile` yielded after applying any desired transformations.
/// After the iterator finishes, remember to call [`finish`](Self::finish).
///
///     let processor = TreeProcessor::new("archive.sfs")?;
///     for mut entry in processor.iter("/home/me/test") {
///         entry.content.mode = 0x1ff; // Set all nodes to be read/writable by anyone
///         match processor.add(entry) {
///             Ok(id) => println!("{}: {}", id, entry.path),
///             Err(_) => println!("Failed adding {}", entry.path),
///         }
///     }
///     processor.finish()?;
///
/// It is safe to process the tree using multiple threads, but it is *the caller's responsibility*
/// to ensure that any out-of-order execution does not cause child nodes to be `add`ed after their
/// parent directories.  If this happens, [`WriteOrder`](SquashfsError::WriteOrder) will be
/// raised and the node will not be added.
pub struct TreeProcessor {
	writer: Mutex<Writer>,
	childmap: Mutex<HashMap<PathBuf, ChildMapEntry>>,
}

impl TreeProcessor {
	/// Create a new `TreeProcessor` for an output file.
	pub fn new<P: AsRef<Path>>(outfile: P) -> Result<Self> {
		let writer = Writer::open(outfile)?;
		Ok(Self { writer: Mutex::new(writer), childmap: Mutex::new(HashMap::new()) })
	}

	/// Add a new file to the archive.
	///
	/// It is not recommended to call this on `SourceFile`s that were not yielded by `iter`.
	pub fn add(&self, mut source: SourceFile) -> Result<u32> {
		let mut childmap = self.childmap.lock().expect("Poisoned lock");
		if let SourceData::Dir(old_children) = &mut source.content.data {
			let mut children = childmap.entry(source.path.clone()).or_insert(ChildMapEntry::new()).finish()?;
			children.extend(old_children);
			source.content.data = SourceData::Dir(Box::new(children.into_iter()));
		}
		let id = self.writer.lock().expect("Poisoned lock").add(source.content)?;
		if let Some(parent) = source.path.parent() {
			childmap.entry(parent.to_path_buf()).or_insert(ChildMapEntry::new()).add(source.path.file_name().expect("Path from walkdir has no file name").to_os_string(), id)?;
		}
		Ok(id)
	}

	/// Finish writing the archive.
	pub fn finish(&self) -> Result<()> {
		self.writer.lock().expect("Poisoned lock").finish()
	}

	fn make_source(&self, entry: DirEntry) -> Result<Source> {
		let metadata = entry.metadata().unwrap();
		let mtime = metadata.modified()?.duration_since(SystemTime::UNIX_EPOCH)?.as_secs() as u32;
		let data = if metadata.file_type().is_dir() {
			SourceData::Dir(Box::new(BTreeMap::new().into_iter()))
		}
		else if metadata.file_type().is_file() {
			SourceData::File(Box::new(std::fs::File::open(entry.path())?))
		}
		else if metadata.file_type().is_symlink() {
			SourceData::Symlink(std::fs::read_link(entry.path())?)
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

	/// Create an iterator over a directory tree, yielding them in a form suitable to pass to
	/// `add`.
	pub fn iter<'a, P: AsRef<Path>>(&'a self, root: P) -> TreeIterator<'a> {
		let tree = WalkDir::new(root).follow_links(false).contents_first(true);
		TreeIterator { processor: self, tree: tree.into_iter() }
	}

	/// Add an entire directory tree to the archive, then finish it.
	///
	/// This is the most basic, bare-bones way to create a full archive from an existing directory
	/// tree.  This offers no way to customize the archive or handle errors gracefully.
	pub fn process<P: AsRef<Path>>(self, root: P) -> Result<()> {
		for entry in self.iter(root) { self.add(entry?)?; }
		self.finish()?;
		Ok(())
	}
}

/// An iterator yielding the nodes in a directory tree in a way suitable for archiving.
///
/// This is created by a [`TreeProcessor`] and the items yielded are intended to be
/// [`add`](TreeProcessor::add)ed to it.
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
			},
			Some(Err(e)) => {
				let path = e.path().map(|x| x.to_string_lossy().into_owned()).unwrap_or("(unknown)".to_string());
				eprintln!("Not processing {}: {}", path, e.to_string());
				self.next()
			},
		}
	}
}
