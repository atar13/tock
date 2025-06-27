use crate::{
    process,
    syscall::{CommandReturn, SyscallDriver},
    ErrorCode, ProcessId,
};

/// Syscall driver number.
pub const DRIVER_NUM: usize = 0x10001;

pub struct SharedLibraryLookup {
    processes: &'static [Option<&'static dyn process::Process>],
}

impl SharedLibraryLookup {
    pub fn new(processes: &'static [Option<&'static dyn process::Process>]) -> SharedLibraryLookup {
        SharedLibraryLookup { processes }
    }
}

impl SyscallDriver for SharedLibraryLookup {
    /// ### `command_num`
    ///
    /// - `0`: Driver existence check, always returns Ok(())
    /// - `1`: Get address of where a given shared library is located
    ///        in flash. Expects `shlib_id` to be the shared library
    ///        identifier. Returns the flash address in the success value.
    /// - `2`: Get memory location where a given shared library is
    ///        loaded in RAM for the current process. Expects
    ///        `shlib_id` to be the shared library identifier. Returns the
    ///        RAM address in the success value.
    fn command(
        &self,
        command_number: usize,
        shlib_id: usize,
        _: usize,
        processid: ProcessId,
    ) -> CommandReturn {
        match command_number {
            0 => CommandReturn::success(),
            1 => {
                // Get the flash address of the shared library.
                match processid.index() {
                    Some(index) => match self.processes.get(index) {
                        Some(Some(process)) => {
                            process.get_shared_library_deps().get(shlib_id).map_or(
                                CommandReturn::failure(ErrorCode::INVAL),
                                |shlib_opt| match shlib_opt {
                                    Some(shlib) => {
                                        let flash_addr = shlib.flash.as_ptr() as usize;
                                        CommandReturn::success_u32_u32(
                                            flash_addr as u32,
                                            shlib.header.length() as u32,
                                        )
                                    }
                                    None => CommandReturn::failure(ErrorCode::INVAL),
                                },
                            )
                        }
                        _ => CommandReturn::failure(ErrorCode::INVAL),
                    },
                    None => CommandReturn::failure(ErrorCode::INVAL),
                }
            }
            2 => {
                // Get the RAM address of the shared library for this process.
                match processid.index() {
                    Some(index) => match self.processes.get(index) {
                        Some(Some(process)) => process
                            .get_shared_library_ram_addresses()
                            .get(shlib_id)
                            .map_or(CommandReturn::failure(ErrorCode::INVAL), |shlib_ram_opt| {
                                match shlib_ram_opt {
                                    Some((ram_addr, _size)) => {
                                        CommandReturn::success_u32(*ram_addr as u32)
                                    }
                                    None => CommandReturn::failure(ErrorCode::INVAL),
                                }
                            }),
                        _ => CommandReturn::failure(ErrorCode::INVAL),
                    },
                    None => CommandReturn::failure(ErrorCode::INVAL),
                }
            }
            _ => CommandReturn::failure(ErrorCode::NOSUPPORT),
        }
    }

    fn allocate_grant(&self, processid: ProcessId) -> Result<(), crate::process::Error> {
        Err(crate::process::Error::KernelError)
    }
}
