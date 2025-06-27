use crate::debug::debug_print;
use crate::syscall::{CommandReturn, SyscallDriver};
use crate::{config, debug, ErrorCode, ProcessId};

/// Errors resulting from trying to load a shared library structure from flash.
#[derive(Debug)]
pub enum SharedLibraryError {
    /// No TBF header was found.
    TbfHeaderNotFound,

    /// The TBF header for the process could not be successfully parsed.
    TbfHeaderParseFailure(tock_tbf::types::TbfParseError),

    /// Not enough flash remaining to parse a process and its header.
    NotEnoughFlash,

    /// This entry in flash is just padding.
    Padding,

    /// This entry is an app, not a shared library
    App,
}

#[derive(Clone, Copy)]
pub struct SharedLibrary {
    /// Process flash segment. This is the entire region of nonvolatile flash
    /// that the process occupies.
    pub flash: &'static [u8],

    /// Collection of pointers to the TBF header in flash.
    pub header: tock_tbf::types::TbfHeader,
}

impl SharedLibrary {
    pub(crate) fn create(
        lib_flash: &'static [u8],
        header_length: usize,
        tbf_version: u16,
    ) -> Result<Self, SharedLibraryError> {
        // Get a slice for just the app header.
        let header_flash = lib_flash
            .get(0..header_length)
            .ok_or(SharedLibraryError::NotEnoughFlash)?;

        // Parse the full TBF header to see if this is a valid app. If the
        // header can't parse, we will error right here.
        let res = tock_tbf::parse::parse_tbf_header(header_flash, tbf_version);

        let tbf_header = match res {
            Ok(x) => x,
            Err(e) => panic!("{:?}", e),
        };

        // If this isn't an app (i.e. it is padding) then we can skip it and do
        // not create a `ProcessBinary` object.
        if !tbf_header.is_app() {
            // Return no process and the full memory slice we were given.
            return Err(SharedLibraryError::Padding);
        }

        if !tbf_header.is_shared_library().unwrap_or(false) {
            return Err(SharedLibraryError::App);
        }

        Ok(Self {
            header: tbf_header,
            flash: lib_flash,
        })
    }

    pub fn get_name(&self) -> Option<&str> {
        self.header.get_package_name()
    }
}
