use std::ptr;
use std::mem;
use std::io;
use std::ffi::c_void;

#[link(name = "kernel32")]
extern "system" {
    fn OpenProcess(dwDesiredAccess: u32, bInheritHandle: i32, dwProcessId: u32) -> *mut c_void;
    fn CloseHandle(hObject: *mut c_void) -> i32;
    fn ReadProcessMemory(
        hProcess: *mut c_void,
        lpBaseAddress: *const c_void,
        lpBuffer: *mut c_void,
        nSize: usize,
        lpNumberOfBytesRead: *mut usize,
    ) -> i32;
    fn WriteProcessMemory(
        hProcess: *mut c_void,
        lpBaseAddress: *mut c_void,
        lpBuffer: *const c_void,
        nSize: usize,
        lpNumberOfBytesWritten: *mut usize,
    ) -> i32;
    fn VirtualQueryEx(
        hProcess: *mut c_void,
        lpAddress: *const c_void,
        lpBuffer: *mut MEMORY_BASIC_INFORMATION,
        dwLength: usize,
    ) -> usize;
    fn GetCurrentProcessId() -> u32;
}

#[repr(C)]
struct MEMORY_BASIC_INFORMATION {
    base_address: *mut c_void,
    allocation_base: *mut c_void,
    allocation_protect: u32,
    region_size: usize,
    state: u32,
    protect: u32,
    r#type: u32,
}

const PROCESS_VM_READ: u32 = 0x0010;
const PROCESS_VM_WRITE: u32 = 0x0020;
const PROCESS_VM_OPERATION: u32 = 0x0008;
const PROCESS_QUERY_INFORMATION: u32 = 0x0400;

#[derive(Debug, Clone)]
pub struct MemoryRegion {
    pub start_address: usize,
    pub size: usize,
    pub is_readable: bool,
    pub is_writable: bool,
    pub is_executable: bool,
    pub protection: u32,
}

pub struct Memory {
    process_handle: *mut c_void,
    regions: Vec<MemoryRegion>,
}

impl Memory {
    pub fn new() -> io::Result<Self> {
        let process_id = unsafe { GetCurrentProcessId() };
        let access = PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION | PROCESS_QUERY_INFORMATION;
        let handle = unsafe { OpenProcess(access, 0, process_id) };
        
        if handle.is_null() {
            return Err(io::Error::new(io::ErrorKind::Other, "Failed to open process"));
        }

        Ok(Memory {
            process_handle: handle,
            regions: Vec::new(),
        })
    }

    pub fn scan_memory(&mut self) -> io::Result<()> {
        let mut address: usize = 0;
        
        while address < usize::MAX {
            let mut mbi: MEMORY_BASIC_INFORMATION = unsafe { mem::zeroed() };
            let result = unsafe {
                VirtualQueryEx(
                    self.process_handle,
                    address as *const c_void,
                    &mut mbi,
                    mem::size_of::<MEMORY_BASIC_INFORMATION>(),
                )
            };

            if result == 0 {
                break;
            }

            if mbi.state == 0x1000 { // MEM_COMMIT
                let region = MemoryRegion {
                    start_address: mbi.base_address as usize,
                    size: mbi.region_size,
                    is_readable: (mbi.protect & 0x1) != 0, // PAGE_NOACCESS
                    is_writable: (mbi.protect & 0x40) != 0, // PAGE_EXECUTE_READWRITE
                    is_executable: (mbi.protect & 0x10) != 0, // PAGE_EXECUTE
                    protection: mbi.protect,
                };
                self.regions.push(region);
            }

            address = mbi.base_address as usize + mbi.region_size;
        }

        Ok(())
    }

    pub fn read_memory<T>(&self, address: usize) -> io::Result<T> {
        let mut buffer: T = unsafe { mem::zeroed() };
        let mut bytes_read: usize = 0;

        let result = unsafe {
            ReadProcessMemory(
                self.process_handle,
                address as *const c_void,
                &mut buffer as *mut T as *mut c_void,
                mem::size_of::<T>(),
                &mut bytes_read,
            )
        };

        if result == 0 {
            return Err(io::Error::new(io::ErrorKind::Other, "Failed to read memory"));
        }

        Ok(buffer)
    }

    pub fn write_memory<T>(&self, address: usize, value: T) -> io::Result<()> {
        let mut bytes_written: usize = 0;

        let result = unsafe {
            WriteProcessMemory(
                self.process_handle,
                address as *mut c_void,
                &value as *const T as *const c_void,
                mem::size_of::<T>(),
                &mut bytes_written,
            )
        };

        if result == 0 {
            return Err(io::Error::new(io::ErrorKind::Other, "Failed to write memory"));
        }

        Ok(())
    }

    pub fn find_pattern(&self, pattern: &[u8], mask: &[bool]) -> io::Result<Option<usize>> {
        for region in &self.regions {
            if !region.is_readable {
                continue;
            }

            let mut buffer = vec![0u8; region.size];
            let mut bytes_read: usize = 0;

            let result = unsafe {
                ReadProcessMemory(
                    self.process_handle,
                    region.start_address as *const c_void,
                    buffer.as_mut_ptr() as *mut c_void,
                    region.size,
                    &mut bytes_read,
                )
            };

            if result == 0 {
                continue;
            }

            for i in 0..(bytes_read - pattern.len()) {
                let mut found = true;
                for j in 0..pattern.len() {
                    if mask[j] && buffer[i + j] != pattern[j] {
                        found = false;
                        break;
                    }
                }
                if found {
                    return Ok(Some(region.start_address + i));
                }
            }
        }

        Ok(None)
    }

    pub fn get_regions(&self) -> &Vec<MemoryRegion> {
        &self.regions
    }
}

impl Drop for Memory {
    fn drop(&mut self) {
        unsafe {
            CloseHandle(self.process_handle);
        }
    }
} 