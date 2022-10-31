extern crate bindgen;

use std::env;
use std::path::PathBuf;

#[cfg(not(feature = "hermetic"))]
fn main() {
	println!("cargo:rustc-link-lib=squashfs");
	println!("cargo:rerun-if-changed=wrapper.h");
	let bindings = bindgen::Builder::default()
		.header("wrapper.h")
		.parse_callbacks(Box::new(bindgen::CargoCallbacks))
		.generate()
		.expect("Failed to generate SquashFS bindings");
	bindings.write_to_file(PathBuf::from(env::var("OUT_DIR").unwrap()).join("bindings.rs")).expect("Failed to write SquashFS bindings");
}

// Don't generate bindings or linking directives if we're building hermetically
#[cfg(feature = "hermetic")]
fn main() { }
