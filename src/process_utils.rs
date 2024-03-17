use std::io::{Error, ErrorKind};
use std::mem;
use windows::Win32::Foundation::{HANDLE, BOOL, CloseHandle};
use windows::Win32::System::Diagnostics::ToolHelp::{CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W, TH32CS_SNAPPROCESS};


pub fn get_process_id_by_name(process_name: &str) -> Result<Option<u32>, Error> {
    unsafe {
        // Create a snapshot of the current system processes
        let snapshot_result = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        let snapshot_handle = match snapshot_result {
            Ok(handle) => handle,
            Err(err) => return Err(err.into()), // Convert windows::Error to std::io::Error
        };

        // Get the first process entry
        let mut entry = PROCESSENTRY32W::default();
        entry.dwSize = mem::size_of::<PROCESSENTRY32W>() as u32;
        match Process32FirstW(snapshot_handle, &mut entry) {
            Ok(_) => {}, // Successfully retrieved the first process entry
            Err(_) => {
                CloseHandle(snapshot_handle);
                return Err(Error::last_os_error());
            }
        }

        // Iterate through process entries
        loop {
            let process_name_str = String::from_utf16_lossy(&entry.szExeFile);
            if process_name_str.trim_end_matches('\0') == process_name {
                CloseHandle(snapshot_handle);
                return Ok(Some(entry.th32ProcessID));
            }
            
            match Process32NextW(snapshot_handle, &mut entry) {
                Ok(_) => {}, // Successfully retrieved the next process entry
                Err(_) => break, // Stop iteration if an error occurs
            }
        }

        // Close the snapshot handle
        CloseHandle(snapshot_handle);

        // Process not found
        Ok(None)
    }
}
