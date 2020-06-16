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

use std::collections::HashMap;
use std::ffi::{CStr, CString};
use std::mem::MaybeUninit;
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
	#[error("Input contains an invalid null character")] NullInput(std::ffi::NulError),
	#[error("{0}: {1}")] LibraryError(String, LibError),
	#[error("{0}: Unknown error {1} in Squashfs library")] UnknownLibraryError(String, i32),
	#[error("{0}: Squashfs library did not return expected value")] LibraryReturnError(String),
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

fn sfs_err(desc: &str) -> Result<()> {
	Err(SquashfsError::LibraryReturnError(desc.to_string()))
}

const NO_XATTRS: u32 = 0xffffffff;

unsafe fn sfs_destroy(obj: *mut sqfs_object_t) {
	((*obj).destroy.expect("Squashfs object did not provide a destory callback"))(obj);
}

pub fn test() -> Result<()> {
	let fname = "/home/matt/Scratch/wikivoyage.sfs";
	unsafe {
		let file = sqfs_open_file(CString::new(fname).map_err(|e| SquashfsError::NullInput(e))?.as_ptr(), SQFS_FILE_OPEN_FLAGS_SQFS_FILE_OPEN_READ_ONLY);
		if file.is_null() { sfs_err("Couldn't open input file")?; }
		let superblock = {
			let mut ret: MaybeUninit<sqfs_super_t> = MaybeUninit::uninit();
			sfs_check(sqfs_super_read(ret.as_mut_ptr(), file), "Couldn't read archive superblock")?;
			ret.assume_init()
		};
		let compressor_config = {
			let mut ret: MaybeUninit<sqfs_compressor_config_t> = MaybeUninit::uninit();
			sqfs_compressor_config_init(ret.as_mut_ptr(), superblock.compression_id as u32, superblock.block_size as u64, SQFS_COMP_FLAG_SQFS_COMP_FLAG_UNCOMPRESS as u16);
			ret.assume_init()
		};
		let compressor = {
			let mut ret: *mut sqfs_compressor_t = ptr::null_mut();
			sfs_check(sqfs_compressor_create(&compressor_config, &mut ret), "Couldn't create compressor")?;
			if ret.is_null() { sfs_err("Couldn't create compressor")?; }
			ret
		};
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
			sfs_check(sqfs_dir_reader_find_by_path(dir_reader, root, CString::new("_meta/info.lua").map_err(|e| SquashfsError::NullInput(e))?.as_ptr(), &mut ret), "Couldn't find path")?;
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
