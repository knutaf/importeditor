use std::{
    path::Path,
    fs::File,
    io,
    slice,
    io::{Read, BufReader},
    cell::RefCell,
    borrow::Cow,
};

use pretty_hex::*;
use zerocopy::{little_endian, FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned};

#[derive(Debug, Clone, FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
#[repr(C, packed)]
struct CoffHeader {
    machine: little_endian::U16,
    number_of_sections: little_endian::U16,
    time_date_stamp: little_endian::U32,
    pointer_to_symbol_table: little_endian::U32,
    number_of_symbols: little_endian::U32,
    size_of_optional_header: little_endian::U16,
    characteristics: little_endian::U16,
}

#[derive(Clone, FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
#[repr(C, packed)]
struct StandardOptionalHeaderPe32Plus {
    major_linker_version: u8,
    minor_linker_version: u8,
    size_of_code: little_endian::U32,
    size_of_initialized_data: little_endian::U32,
    size_of_uninitialized_data: little_endian::U32,
    address_of_entry_point: little_endian::U32,
    base_of_code: little_endian::U32,
}

#[derive(Debug, Clone, FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
#[repr(C, packed)]
struct WindowsSpecificOptionalHeaderPe32Plus {
    image_base: little_endian::U64,
    section_alignment: little_endian::U32,
    file_alignment: little_endian::U32,
    major_operating_system_version: little_endian::U16,
    minor_operating_system_version: little_endian::U16,
    major_image_version: little_endian::U16,
    minor_image_version: little_endian::U16,
    major_subsystem_version: little_endian::U16,
    minor_subsystem_version: little_endian::U16,
    win32_version_value: little_endian::U32,
    size_of_image: little_endian::U32,
    size_of_headers: little_endian::U32,
    checksum: little_endian::U32,
    subsystem: little_endian::U16,
    dll_characteristics: little_endian::U16,
    size_of_stack_reserve: little_endian::U64,
    size_of_stack_commit: little_endian::U64,
    size_of_heap_reserve: little_endian::U64,
    size_of_heap_commit: little_endian::U64,
    loader_flags: little_endian::U32,
    number_of_rva_and_sizes: little_endian::U32,
}

#[derive(Clone, FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
#[repr(C, packed)]
struct ImageDataDirectory {
    virtual_address: little_endian::U32,
    size: little_endian::U32,
}

#[derive(Clone, FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
#[repr(C, packed)]
struct ImageImportDescriptor {
    characteristics_or_original_first_thunk: little_endian::U32,
    time_date_stamp: little_endian::U32,
    forwarder_chain: little_endian::U32,
    name: little_endian::U32,
    first_thunk: little_endian::U32,
}

impl ImageImportDescriptor {
    fn is_zero(&self) -> bool {
        self.characteristics_or_original_first_thunk == 0 &&
        self.time_date_stamp == 0 &&
        self.forwarder_chain == 0 &&
        self.name == 0 &&
        self.first_thunk == 0
    }
}

#[derive(Clone, FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
#[repr(C, packed)]
struct SectionHeader {
    name: [u8; 8],
    virtual_size: little_endian::U32,
    virtual_address: little_endian::U32,
    size_of_raw_data: little_endian::U32,
    pointer_to_raw_data: little_endian::U32,
    pointer_to_relocations: little_endian::U32,
    pointer_to_line_numbers: little_endian::U32,
    number_of_relocations: little_endian::U16,
    number_of_line_numbers: little_endian::U16,
    characteristics: little_endian::U32,
}

fn read_struct<T, R: Read>(read: &mut R) -> io::Result<T> {
    let num_bytes = ::std::mem::size_of::<T>();
    unsafe {
        let mut s = ::std::mem::uninitialized();
        let mut buffer = slice::from_raw_parts_mut(&mut s as *mut T as *mut u8, num_bytes);
        match read.read_exact(buffer) {
            Ok(()) => Ok(s),
            Err(e) => {
                ::std::mem::forget(s);
                Err(e)
            }
        }
    }
}

fn parse_ascii_string(src: &[u8]) -> Cow<'_, str>  {
    let mut len = 0;
    while len < src.len() && src[len] != 0 {
        len += 1;
    }

    String::from_utf8_lossy(&src[0..len])
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut contents = Vec::new();
    File::open(std::env::args().nth(1).unwrap())?.read_to_end(&mut contents)?;

    // made it read-only
    let contents = contents;

    let mut new_contents = contents.clone();

    let data = RefCell::new(&contents[..]);
    let last_offset = RefCell::new(0);
    let current_offset = RefCell::new(0);

    let mut pr = |size| -> Result<(), Box<dyn std::error::Error>> {
        let cur = *current_offset.borrow();
        *last_offset.borrow_mut() = cur;

        let mut data = data.borrow_mut();
        *data = &contents[cur..cur + size];
        *current_offset.borrow_mut() += size;
        println!("{:?}", data.hex_dump());
        Ok(())
    };

    pr(0x3c)?;

    pr(4)?;

    let signature_offset = u32::from_le_bytes(data.borrow().clone().try_into().unwrap());
    println!("signature at 0x{:x}", signature_offset);

    println!("skipping");
    let skip = signature_offset as usize - *current_offset.borrow();
    pr(skip)?;

    println!("signature");
    pr(4)?;

    println!("coff header");
    pr(std::mem::size_of::<CoffHeader>())?;
    let coff_header = CoffHeader::ref_from_bytes(&*data.borrow()).unwrap().clone();

    // Add another section that will contain the new import table
    {
        let last_offset = *last_offset.borrow();
        let mut coff_header = CoffHeader::mut_from_bytes(&mut new_contents[last_offset..last_offset + std::mem::size_of::<CoffHeader>()]).unwrap();
        coff_header.number_of_sections += 1;
    }

    println!("coff header: {:?}", coff_header);

    println!("magic");
    pr(2)?;

    let magic = u16::from_le_bytes(data.borrow().clone().try_into().unwrap());
    if magic != 0x20b {
        panic!("only supports x64 binaries");
    }

    println!("standard optional header");
    pr(std::mem::size_of::<StandardOptionalHeaderPe32Plus>())?;
    let standard_header = StandardOptionalHeaderPe32Plus::ref_from_bytes(&*data.borrow()).unwrap().clone();

    println!("size of code: {}", standard_header.size_of_code);

    println!("windows optional header");
    pr(std::mem::size_of::<WindowsSpecificOptionalHeaderPe32Plus>())?;
    let windows_header = WindowsSpecificOptionalHeaderPe32Plus::ref_from_bytes(&*data.borrow()).unwrap().clone();

    println!("windows header: {:?}", windows_header);

    let mut import_table_dir = None;
    for i in 0..windows_header.number_of_rva_and_sizes.get() {
        match i {
            0 => println!("export table dir"),
            1 => println!("import table dir"),
            _ => {},
        }

        pr(std::mem::size_of::<ImageDataDirectory>())?;

        if i == 1 {
            import_table_dir = Some(ImageDataDirectory::ref_from_bytes(&*data.borrow()).unwrap().clone());
        }
    }

    let import_table_dir = import_table_dir.unwrap();

    println!("addr: 0x{:x}, size: {}", import_table_dir.virtual_address, import_table_dir.size);

    // Loop through the imports table
    let mut rest_of_image_imports = &contents[import_table_dir.virtual_address.get() as usize ..];

    loop {
        let (image_import_entry, rest) = ImageImportDescriptor::ref_from_prefix(rest_of_image_imports).unwrap();
        if image_import_entry.is_zero() {
            break;
        }

        println!("name addr: {:x}", image_import_entry.name);
        rest_of_image_imports = rest;

        let image_name = parse_ascii_string(&contents[image_import_entry.name.get() as usize ..]);
        println!("name: {}", image_name);

        // Loop through the functions imported from each module in the import table
        let mut rest_of_thunks = &contents[image_import_entry.characteristics_or_original_first_thunk.get() as usize ..];
        loop {
            let (thunk_address, rest) = little_endian::U64::ref_from_prefix(rest_of_thunks).unwrap();
            if thunk_address.get() == 0 {
                break;
            }

            rest_of_thunks = rest;

            if (thunk_address.get() & 0x8000000000000000) != 0 {
                println!("    Ordinal {}", thunk_address.get() & 0x7fffffffffffffff);
            } else {
                let import_by_name = &contents[thunk_address.get() as usize ..];
                let (hint, name_prefix) = little_endian::U16::ref_from_prefix(import_by_name).unwrap();
                println!("    {} - {}", hint.get(), parse_ascii_string(name_prefix));
            }
        }

        // Loop through the import address table, which should have identical contents
        println!("iat");
        let mut rest_of_thunks = &contents[image_import_entry.first_thunk.get() as usize ..];
        loop {
            let (thunk_address, rest) = little_endian::U64::ref_from_prefix(rest_of_thunks).unwrap();
            if thunk_address.get() == 0 {
                break;
            }

            rest_of_thunks = rest;

            if (thunk_address.get() & 0x8000000000000000) != 0 {
                println!("    Ordinal {}", thunk_address.get() & 0x7fffffffffffffff);
            } else {
                let import_by_name = &contents[thunk_address.get() as usize ..];
                let (hint, name_prefix) = little_endian::U16::ref_from_prefix(import_by_name).unwrap();
                println!("    {} - {}", hint.get(), parse_ascii_string(name_prefix));
            }
        }
    }

    /* experiments - not needed
    {
        let (mut entry, _) = ImageImportDescriptor::mut_from_prefix(&mut new_contents[import_table_dir.virtual_address.get() as usize ..]).unwrap();
        //entry.name = 0x211479.into();
        entry.name = 0x19b032.into();
    }
    {
        let (entry, _) = ImageImportDescriptor::ref_from_prefix(&new_contents[import_table_dir.virtual_address.get() as usize ..]).unwrap();
        println!("name: {}", parse_ascii_string(&new_contents[entry.name.get() as usize ..]));
    }
    */

    // Dump all the other section headers
    let mut next_raw_section = 0;
    for i in 0..coff_header.number_of_sections.get() {
        println!("section header at 0x{:x}", *current_offset.borrow());
        pr(std::mem::size_of::<SectionHeader>())?;
        let section_header = SectionHeader::ref_from_bytes(&*data.borrow()).unwrap().clone();
        println!("section {}. addr {:x}, size {}, raw size {}", parse_ascii_string(&section_header.name), section_header.virtual_address, section_header.virtual_size, section_header.size_of_raw_data);

        next_raw_section = section_header.virtual_address.get() + section_header.size_of_raw_data.get();
    }

    // Add a new section header after the other ones
    {
        let current_offset = *current_offset.borrow();
        let mut section_header = SectionHeader::mut_from_bytes(&mut new_contents[current_offset..current_offset + std::mem::size_of::<SectionHeader>()]).unwrap();

        // Arbitrary name
        section_header.name = *b".impt2\0\0";

        // TODO: probably needs to be larger than this, but wanted to do a test where I just change one string to point into it, to test out that the rest of the method will work
        section_header.virtual_size = 20.into();
        section_header.virtual_address = next_raw_section.into();
        section_header.size_of_raw_data = 0x1000.into();
        section_header.pointer_to_raw_data = section_header.virtual_address;
        section_header.pointer_to_relocations = 0.into();
        section_header.pointer_to_line_numbers = 0.into();
        section_header.number_of_relocations = 0.into();
        section_header.number_of_line_numbers = 0.into();
        section_header.characteristics =
            (0x00000040 | // IMAGE_SCN_CNT_INITIALIZED_DATA
             0x10000000 | // IMAGE_SCN_MEM_SHARED
             0x40000000)   // IMAGE_SCN_MEM_READ
            .into();

        println!("new section {}. addr {:x}, size {}, raw size {}", parse_ascii_string(&section_header.name), section_header.virtual_address, section_header.virtual_size, section_header.size_of_raw_data);
    }

    // TODO: add space at the end of the file with the contents of the next section

    // write out to a new binary
    let outpath = format!("{}2", std::env::args().nth(1).unwrap());
    std::fs::write(outpath, &new_contents)?;
    Ok(())
}
