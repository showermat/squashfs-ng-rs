#![allow(dead_code)] // FIXME

extern crate libc;

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

const NO_XATTRS: u32 = 0xffffffff;

unsafe fn destroy(obj: *mut sqfs_object_t) {
	((*obj).destroy.unwrap())(obj);
}

pub fn test() {
	let fname = "/home/matt/Scratch/wikivoyage.sfs";
	unsafe {
		let file = sqfs_open_file(CString::new(fname).unwrap().as_ptr(), SQFS_FILE_OPEN_FLAGS_SQFS_FILE_OPEN_READ_ONLY);
		if file.is_null() { panic!("Couldn't open file"); }
		let superblock = {
			let mut ret: MaybeUninit<sqfs_super_t> = MaybeUninit::uninit();
			if sqfs_super_read(ret.as_mut_ptr(), file) != 0 { panic!("Couldn't get superblock"); }
			ret.assume_init()
		};
		let compressor_config = {
			let mut ret: MaybeUninit<sqfs_compressor_config_t> = MaybeUninit::uninit();
			sqfs_compressor_config_init(ret.as_mut_ptr(), superblock.compression_id as u32, superblock.block_size as u64, SQFS_COMP_FLAG_SQFS_COMP_FLAG_UNCOMPRESS as u16);
			ret.assume_init()
		};
		let compressor = {
			let mut ret: *mut sqfs_compressor_t = ptr::null_mut();
			if sqfs_compressor_create(&compressor_config, &mut ret) != 0 { panic!("Couldn't create compressor"); }
			if ret.is_null() { panic!("No error reported creating compressor, but got empty result"); }
			ret
		};
		let dir_reader = sqfs_dir_reader_create(&superblock, compressor, file, 0);
		if dir_reader.is_null() { panic!("Couldn't create directory reader"); }
		let root = {
			let mut ret: *mut sqfs_inode_generic_t = ptr::null_mut();
			if sqfs_dir_reader_get_root_inode(dir_reader, &mut ret) != 0 { panic!("Couldn't get root inode"); }
			if ret.is_null() { panic!("No error reported getting root inode, but got empty result"); }
			ret
		};
		if sqfs_dir_reader_open_dir(dir_reader, root, 0) != 0 { panic!("Couldn't open root directory"); }
		let mut dir_entry: *mut sqfs_dir_entry_t = ptr::null_mut();
		loop {
			let readres = sqfs_dir_reader_read(dir_reader, &mut dir_entry);
			if readres > 0 { break; }
			if readres < 0 { panic!("Couldn't list directory contents"); }
			if dir_entry.is_null() { panic!("No error reported reading directory, but got empty result"); }
			let name_bytes = (*dir_entry).name.as_slice((*dir_entry).size as usize + 1);
			let name = String::from_utf8_lossy(name_bytes).into_owned();
			println!("{}", name);
		}
		let inode = {
			let mut ret: *mut sqfs_inode_generic_t = ptr::null_mut();
			if sqfs_dir_reader_find_by_path(dir_reader, root, CString::new("_meta/info.lua").unwrap().as_ptr(), &mut ret) != 0 { panic!("Couldn't get internal inode"); }
			if ret.is_null() { panic!("No error reported getting internal inode, but got empty result"); }
			ret
		};
		let mut size: u64 = 0;
		sqfs_inode_get_file_size(inode, &mut size);
		println!("File is {} bytes", size);
		let data_reader = sqfs_data_reader_create(file, superblock.block_size as u64, compressor, 0);
		if data_reader.is_null() { panic!("Couldn't create data reader"); }
		if sqfs_data_reader_load_fragment_table(data_reader, &superblock) != 0 { panic!("Couldn't load fragment table"); };
		let mut off = 0 as u64;
		let mut content = String::new();
		let mut buf: Vec<u8> = vec![0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
		loop {
			let readres = sqfs_data_reader_read(data_reader, inode, off, buf.as_mut_ptr() as *mut libc::c_void, buf.len() as u32);
			if readres == 0 { break; }
			if readres < 0 { panic!(format!("Couldn't read from file: {}", readres)); }
			content.push_str(&String::from_utf8_lossy(&buf[0..readres as usize]));
			off += readres as u64;
		}
		println!("{}", content);
		let xattr_reader = sqfs_xattr_reader_create(0);
		if sqfs_xattr_reader_load(xattr_reader, &superblock, file, compressor) != 0 { panic!("Couldn't create xattr reader"); }
		let mut xattr_idx: u32 = NO_XATTRS;
		if sqfs_inode_get_xattr_index(inode, &mut xattr_idx) != 0 { panic!("Couldn't get xattr index for inode"); }
		let xattr_id = {
			let mut ret: MaybeUninit<sqfs_xattr_id_t> = MaybeUninit::uninit();
			if sqfs_xattr_reader_get_desc(xattr_reader, xattr_idx, ret.as_mut_ptr()) != 0 { panic!("Couldn't get xattr ID for inode"); }
			ret.assume_init()
		};
		let xattr_type = SQFS_XATTR_TYPE_SQFS_XATTR_USER;
		let mut xattrs: HashMap<Vec<u8>, Vec<u8>> = HashMap::new();
		if sqfs_xattr_reader_seek_kv(xattr_reader, &xattr_id) != 0 { panic!("Couldn't seek to xattr location"); }
		for _ in 0..xattr_id.count {
			let mut xattr_key: *mut sqfs_xattr_entry_t = ptr::null_mut();
			if sqfs_xattr_reader_read_key(xattr_reader, &mut xattr_key) != 0 { panic!("Couldn't read xattr key"); }
			if xattr_key.is_null() { panic!("No error reported reading xattr key, but got an empty result"); }
			if (*xattr_key).type_ as u32 & SQFS_XATTR_TYPE_SQFS_XATTR_FLAG_OOL != 0 {
				// TODO
			}
			let prefixlen = CStr::from_ptr(sqfs_get_xattr_prefix((*xattr_key).type_ as u32)).to_bytes().len();
			let mut xattr_val: *mut sqfs_xattr_value_t = ptr::null_mut();
			if sqfs_xattr_reader_read_value(xattr_reader, xattr_key, &mut xattr_val) != 0 { panic!("Couldn't read xattr value"); }
			if xattr_val.is_null() { panic!("No error reported reading xattr value, but got an empty result"); }
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
		destroy(xattr_reader as *mut sqfs_object_t);
		destroy(data_reader as *mut sqfs_object_t);
		libc::free(inode as *mut libc::c_void);
		libc::free(dir_entry as *mut libc::c_void);
		libc::free(root as *mut libc::c_void);
		destroy(dir_reader as *mut sqfs_object_t);
		destroy(file as *mut sqfs_object_t);
	}
}
