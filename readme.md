# squashfs-ng-rs

This library wraps the [squashfs-tools-ng](https://github.com/AgentD/squashfs-tools-ng) libraries, providing tools for reading and writing SquashFS archives.  It aims to provide safe high-level abstractions over the lower-level interface provided by the underlying library.

    // Create an archive from a file hierarchy on disk
    use squashfs::write::TreeProcessor;
    TreeProcessor::new("archive.sfs")?.process("/path/to/directory")?;

    // Read the contents of a file from an archive
    use squashfs::read::Archive;
    let archive = Archive::open("archive.sfs")?;
    match archive.get("/etc/passwd")? {
        None => println!("File not present"),
        Some(node) => if let Data::File(file) = node.data()? {
            println!("{}", file.to_string()?);
        },
    }

Squashfs-tools-ng must be installed to build or use this library -- for example, [squashfs-tools-ng](https://aur.archlinux.org/packages/squashfs-tools-ng) in the AUR for Arch Linux.

**See [the API documentation](http://docs.rs/squashfs-ng) for more.**
