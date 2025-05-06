mod memory;

use std::io;
use memory::Memory;

fn main() -> io::Result<()> {
    // Create a new memory editor instance
    let mut memory = Memory::new()?;
    
    // Scan memory regions
    memory.scan_memory()?;
    
    // Print memory regions
    println!("Found {} memory regions:", memory.get_regions().len());
    for (i, region) in memory.get_regions().iter().enumerate() {
        println!("Region {}: 0x{:X} - 0x{:X} (Size: 0x{:X})", 
            i, 
            region.start_address, 
            region.start_address + region.size,
            region.size
        );
    }
    
    // Example of reading memory from the first region
    if let Some(first_region) = memory.get_regions().first() {
        match memory.read_memory::<u32>(first_region.start_address) {
            Ok(value) => println!("Read value at 0x{:X}: {}", first_region.start_address, value),
            Err(e) => println!("Failed to read memory: {}", e),
        }
    }

    // Example of pattern scanning
    let pattern = [0x90, 0x90, 0x90]; // NOP pattern
    let mask = [true, true, true];
    match memory.find_pattern(&pattern, &mask)? {
        Some(address) => println!("Found pattern at address: 0x{:X}", address),
        None => println!("Pattern not found"),
    }

    Ok(())
}
