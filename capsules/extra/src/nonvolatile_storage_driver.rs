// Licensed under the Apache License, Version 2.0 or the MIT License.
// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright Tock Contributors 2022.

//! This provides kernel and userspace access to nonvolatile memory.
//!
//! This is an initial implementation that does not provide safety for
//! individual userland applications. Each application has full access to
//! the entire memory space that has been provided to userland. Future revisions
//! should update this to limit applications to only their allocated regions.
//!
//! However, the kernel accessible memory does not have to be the same range
//! as the userspace accessible address space. The kernel memory can overlap
//! if desired, or can be a completely separate range.
//!
//! Here is a diagram of the expected stack with this capsule:
//! Boxes are components and between the boxes are the traits that are the
//! interfaces between components. This capsule provides both a kernel and
//! userspace interface.
//!
//! ```text
//! +--------------------------------------------+     +--------------+
//! |                                            |     |              |
//! |                  kernel                    |     |  userspace   |
//! |                                            |     |              |
//! +--------------------------------------------+     +--------------+
//!  hil::nonvolatile_storage::NonvolatileStorage       kernel::Driver
//! +-----------------------------------------------------------------+
//! |                                                                 |
//! | capsules::nonvolatile_storage_driver::NonvolatileStorage (this) |
//! |                                                                 |
//! +-----------------------------------------------------------------+
//!            hil::nonvolatile_storage::NonvolatileStorage
//! +-----------------------------------------------------------------+
//! |                                                                 |
//! |               Physical nonvolatile storage driver               |
//! |                                                                 |
//! +-----------------------------------------------------------------+
//! ```
//!
//! Example instantiation:
//!
//! ```rust
//! # use kernel::static_init;
//!
//! let nonvolatile_storage = static_init!(
//!     capsules::nonvolatile_storage_driver::NonvolatileStorage<'static>,
//!     capsules::nonvolatile_storage_driver::NonvolatileStorage::new(
//!         fm25cl,                      // The underlying storage driver.
//!         board_kernel.create_grant(&grant_cap),     // Storage for app-specific state.
//!         3000,                        // The byte start address for the userspace
//!                                      // accessible memory region.
//!         2000,                        // The length of the userspace region.
//!         0,                           // The byte start address of the region
//!                                      // that is accessible by the kernel.
//!         3000,                        // The length of the kernel region.
//!         &mut capsules::nonvolatile_storage_driver::BUFFER));
//! hil::nonvolatile_storage::NonvolatileStorage::set_client(fm25cl, nonvolatile_storage);
//! ```

use core::cell::Cell;
use core::cmp;

use kernel::grant::{AllowRoCount, AllowRwCount, Grant, UpcallCount};
use kernel::{debug, hil};
use kernel::processbuffer::{ReadableProcessBuffer, WriteableProcessBuffer};
use kernel::syscall::{CommandReturn, SyscallDriver};
use kernel::utilities::cells::{OptionalCell, TakeCell};
use kernel::{ErrorCode, ProcessId};

/// Syscall driver number.
use capsules_core::driver;
pub const DRIVER_NUM: usize = driver::NUM::NvmStorage as usize;

/// IDs for subscribed upcalls.
mod upcall {
    /// Read done callback.
    pub const READ_DONE: usize = 0;
    /// Write done callback.
    pub const WRITE_DONE: usize = 1;
    /// Number of upcalls.
    pub const COUNT: u8 = 2;
}

/// Ids for read-only allow buffers
mod ro_allow {
    /// Setup a buffer to write bytes to the nonvolatile storage.
    pub const WRITE: usize = 0;
    /// The number of allow buffers the kernel stores for this grant
    pub const COUNT: u8 = 1;
}

/// Ids for read-write allow buffers
mod rw_allow {
    /// Setup a buffer to read from the nonvolatile storage into.
    pub const READ: usize = 0;
    /// The number of allow buffers the kernel stores for this grant
    pub const COUNT: u8 = 1;
}

pub const BUF_LEN: usize = 512;

#[derive(Clone, Copy, PartialEq)]
pub enum NonvolatileCommand {
    UserspaceRead,
    UserspaceWrite,
    KernelRead,
    KernelWrite,
}

#[derive(Clone, Copy)]
pub enum NonvolatileUser {
    App { processid: ProcessId },
    Kernel,
}

/// Describes a region of nonvolatile memory that is assigned to a
/// certain app. 
pub struct NonvolatileAppRegion {
    /// Absolute address to describe where an app's nonvolatile region
    /// starts.
    offset: usize, 
    /// How many bytes allocated to a certain app.
    length: usize
}

pub struct App {
    pending_command: bool,
    command: NonvolatileCommand,
    offset: usize,
    length: usize,
    region: Option<NonvolatileAppRegion>
}

impl Default for App {
    fn default() -> App {
        App {
            pending_command: false,
            command: NonvolatileCommand::UserspaceRead,
            offset: 0,
            length: 0,
            region: None
        }
    }
}

pub struct NonvolatileStorage<'a> {
    // The underlying physical storage device.
    driver: &'a dyn hil::nonvolatile_storage::NonvolatileStorage<'a>,
    // Per-app state.
    apps: Grant<
        App,
        UpcallCount<{ upcall::COUNT }>,
        AllowRoCount<{ ro_allow::COUNT }>,
        AllowRwCount<{ rw_allow::COUNT }>,
    >,

    // Internal buffer for copying appslices into.
    buffer: TakeCell<'static, [u8]>,
    // What issued the currently executing call. This can be an app or the kernel.
    current_user: OptionalCell<NonvolatileUser>,

    // The first byte that is accessible from userspace.
    userspace_start_address: usize,
    // How many bytes allocated to userspace.
    userspace_length: usize,
    // The first byte that is accessible from the kernel.
    kernel_start_address: usize,
    // How many bytes allocated to kernel.
    kernel_length: usize,

    // Optional client for the kernel. Only needed if the kernel intends to use
    // this nonvolatile storage.
    kernel_client: OptionalCell<&'a dyn hil::nonvolatile_storage::NonvolatileStorageClient>,
    // Whether the kernel is waiting for a read/write.
    kernel_pending_command: Cell<bool>,
    // Whether the kernel wanted a read/write.
    kernel_command: Cell<NonvolatileCommand>,
    // Holder for the buffer passed from the kernel in case we need to wait.
    kernel_buffer: TakeCell<'static, [u8]>,
    // How many bytes to read/write from the kernel buffer.
    kernel_readwrite_length: Cell<usize>,
    // Where to read/write from the kernel request.
    kernel_readwrite_address: Cell<usize>,

    // How many bytes each app should be allocted
    app_region_size: usize,
    // Absolute address of next region of userspace that's unallocated
    // to an app yet. Each time an app uses this capsule, a new
    // region of storage will be handed out and this address will
    // point to a new unallocated region. 
    start_address_unallocated_app_region: Cell<usize>,
}

impl<'a> NonvolatileStorage<'a> {
    pub fn new(
        driver: &'a dyn hil::nonvolatile_storage::NonvolatileStorage<'a>,
        grant: Grant<
            App,
            UpcallCount<{ upcall::COUNT }>,
            AllowRoCount<{ ro_allow::COUNT }>,
            AllowRwCount<{ rw_allow::COUNT }>,
        >,
        userspace_start_address: usize,
        userspace_length: usize,
        kernel_start_address: usize,
        kernel_length: usize,
        app_region_size: usize,
        buffer: &'static mut [u8],
    ) -> NonvolatileStorage<'a> {
        NonvolatileStorage {
            driver: driver,
            apps: grant,
            buffer: TakeCell::new(buffer),
            current_user: OptionalCell::empty(),
            userspace_start_address: userspace_start_address,
            userspace_length: userspace_length,
            kernel_start_address: kernel_start_address,
            kernel_length: kernel_length,
            kernel_client: OptionalCell::empty(),
            kernel_pending_command: Cell::new(false),
            kernel_command: Cell::new(NonvolatileCommand::KernelRead),
            kernel_buffer: TakeCell::empty(),
            kernel_readwrite_length: Cell::new(0),
            kernel_readwrite_address: Cell::new(0),
            app_region_size: app_region_size,
            start_address_unallocated_app_region: Cell::new(userspace_start_address),
        }
    }

    fn assign_app_region(&self, processid: ProcessId) -> Result<(), ErrorCode> {
        let res = self.apps.enter(processid, |app, _kernel_data| {
            // if this app's region is already allocated, we're good
            if app.region.is_some() { 
                return Ok(());
            }

            // check that allocating the next region of flash won't go over
            // the userspace boundaries
            let userspace_end = self.userspace_start_address + self.userspace_length;
            let new_region_start = self.start_address_unallocated_app_region.get();
            let new_region_end = self.start_address_unallocated_app_region.get() + self.app_region_size;

            if new_region_start < self.userspace_start_address ||
                new_region_start >= userspace_end || 
                new_region_end > userspace_end
            {
                return Err(ErrorCode::FAIL);
            }

            app.region = Some(NonvolatileAppRegion{
                offset: new_region_start,
                length: self.app_region_size
            });
            Ok(())
        });

        match res {
            // handle failure to allocate new region
            Ok(closure_res) => match closure_res {
                Ok(_) => Ok(()),
                Err(e) => Err(e)
            },
            // handle failure to enter the grant 
            Err(_) => Err(ErrorCode::FAIL),
        }
    }

    fn check_userspace_access(&self, offset: usize, length: usize, processid: Option<ProcessId>) -> Result<(), ErrorCode> {
        // check if access is within entire userspace region
        if offset >= self.userspace_length
            || length > self.userspace_length
            || offset + length > self.userspace_length
        {
            return Err(ErrorCode::INVAL);
        }

        // check that access is within this app's isolated nonvolatile region. 
        // this is to prevent an app from reading/writing to another app's
        // nonvolatile storage.
        let res = processid.map_or(Err(ErrorCode::FAIL), |processid| {
            // enter the grant to query what the app's 
            // nonvolatile region is
            self.apps.enter(processid, |app, _kernel_data| {
                match &app.region {
                    Some(app_region) => {
                        debug!("Trying to access offset {} and length {}; Userspace offset {} and length {}. App region offset {} and length {}",
                            offset,
                            length,
                            self.userspace_start_address,
                            self.userspace_length,
                            app_region.offset,
                            app_region.length);
                        // let app_region_start = app_region.offset;
                        // let app_region_end = app_region.offset + app_region.length;

                        if  offset >= app_region.length 
                            || length > app_region.length 
                            || offset + length >= app_region.length
                        {
                            debug!("out of range for userspace access");
                            return Err(ErrorCode::INVAL);
                        }

                        Ok(())
                    },

                    // fail if this app's nonvolatile region hasn't been assigned
                    None => return Err(ErrorCode::FAIL),
                }
            }).unwrap_or_else(|err| Err(err.into()))
        });

        if res.is_err() {
            return res;
        }

        Ok(())
    }

    fn check_kernel_access(&self, offset: usize, length: usize) -> Result<(), ErrorCode> {
        // Because the kernel uses the NonvolatileStorage interface,
        // its calls are absolute addresses.
        if offset < self.kernel_start_address
            || offset >= self.kernel_start_address + self.kernel_length
            || length > self.kernel_length
            || offset + length > self.kernel_start_address + self.kernel_length
        {
            return Err(ErrorCode::INVAL);
        }

        Ok(())
    }

    // Check so see if we are doing something. If not, go ahead and do this
    // command. If so, this is queued and will be run when the pending
    // command completes.
    fn enqueue_command(
        &self,
        command: NonvolatileCommand,
        offset: usize,
        length: usize,
        processid: Option<ProcessId>,
    ) -> Result<(), ErrorCode> {
        // Do different bounds check depending on userpace vs kernel accesses
        match command {
            NonvolatileCommand::UserspaceRead | NonvolatileCommand::UserspaceWrite => {
                let res = self.check_userspace_access(offset, length, processid);
                if res.is_err() {
                    return res;
                }
            }
            NonvolatileCommand::KernelRead | NonvolatileCommand::KernelWrite => {
                let res = self.check_kernel_access(offset, length);
                if res.is_err() {
                    return res;
                }
            }
        }

        // Do very different actions if this is a call from userspace
        // or from the kernel.
        match command {
            NonvolatileCommand::UserspaceRead | NonvolatileCommand::UserspaceWrite => {
                processid.map_or(Err(ErrorCode::FAIL), |processid| {
                    self.apps
                        .enter(processid, |app, kernel_data| {
                            // Get the length of the correct allowed buffer.
                            let allow_buf_len = match command {
                                NonvolatileCommand::UserspaceRead => kernel_data
                                    .get_readwrite_processbuffer(rw_allow::READ)
                                    .map_or(0, |read| read.len()),
                                NonvolatileCommand::UserspaceWrite => kernel_data
                                    .get_readonly_processbuffer(ro_allow::WRITE)
                                    .map_or(0, |read| read.len()),
                                _ => 0,
                            };

                            // Check that it exists.
                            if allow_buf_len == 0 || self.buffer.is_none() {
                                return Err(ErrorCode::RESERVE);
                            }

                            // Shorten the length if the application gave us nowhere to
                            // put it.
                            let active_len = cmp::min(length, allow_buf_len);

                            // First need to determine if we can execute this or must
                            // queue it.
                            if self.current_user.is_none() {
                                // No app is currently using the underlying storage.
                                // Mark this app as active, and then execute the command.
                                self.current_user.set(NonvolatileUser::App {
                                    processid: processid,
                                });

                                // Need to copy bytes if this is a write!
                                if command == NonvolatileCommand::UserspaceWrite {
                                    let _ = kernel_data
                                        .get_readonly_processbuffer(ro_allow::WRITE)
                                        .and_then(|write| {
                                            write.enter(|app_buffer| {
                                                self.buffer.map(|kernel_buffer| {
                                                    // Check that the internal buffer and the buffer that was
                                                    // allowed are long enough.
                                                    let write_len =
                                                        cmp::min(active_len, kernel_buffer.len());

                                                    let d = &app_buffer[0..write_len];
                                                    for (i, c) in kernel_buffer[0..write_len]
                                                        .iter_mut()
                                                        .enumerate()
                                                    {
                                                        *c = d[i].get();
                                                    }
                                                });
                                            })
                                        });
                                }

                                let app_region_start = match &app.region {
                                    Some(region) => region.offset,
                                    None => return Err(ErrorCode::FAIL),
                                }; 
                                debug!("performing access at {} for length {}", app_region_start + offset, active_len);

                                // Userspace accesses start at 0 which is the start of the app's region.
                                self.userspace_call_driver(command, app_region_start + offset, active_len)
                            } else {
                                // Some app is using the storage, we must wait.
                                if app.pending_command {
                                    // No more room in the queue, nowhere to store this
                                    // request.
                                    Err(ErrorCode::NOMEM)
                                } else {
                                    // We can store this, so lets do it.
                                    app.pending_command = true;
                                    app.command = command;
                                    app.offset = offset;
                                    app.length = active_len;
                                    Ok(())
                                }
                            }
                        })
                        .unwrap_or_else(|err| Err(err.into()))
                })
            }
            NonvolatileCommand::KernelRead | NonvolatileCommand::KernelWrite => {
                self.kernel_buffer
                    .take()
                    .map_or(Err(ErrorCode::NOMEM), |kernel_buffer| {
                        let active_len = cmp::min(length, kernel_buffer.len());

                        // Check if there is something going on.
                        if self.current_user.is_none() {
                            // Nothing is using this, lets go!
                            self.current_user.set(NonvolatileUser::Kernel);

                            match command {
                                NonvolatileCommand::KernelRead => {
                                    self.driver.read(kernel_buffer, offset, active_len)
                                }
                                NonvolatileCommand::KernelWrite => {
                                    self.driver.write(kernel_buffer, offset, active_len)
                                }
                                _ => Err(ErrorCode::FAIL),
                            }
                        } else {
                            if self.kernel_pending_command.get() {
                                Err(ErrorCode::NOMEM)
                            } else {
                                self.kernel_pending_command.set(true);
                                self.kernel_command.set(command);
                                self.kernel_readwrite_length.set(active_len);
                                self.kernel_readwrite_address.set(offset);
                                self.kernel_buffer.replace(kernel_buffer);
                                Ok(())
                            }
                        }
                    })
            }
        }
    }

    fn userspace_call_driver(
        &self,
        command: NonvolatileCommand,
        offset: usize,
        length: usize,
    ) -> Result<(), ErrorCode> {
        // Calculate where we want to actually read from in the physical
        // storage.
        let physical_address = offset + self.userspace_start_address;

        self.buffer
            .take()
            .map_or(Err(ErrorCode::RESERVE), |buffer| {
                // Check that the internal buffer and the buffer that was
                // allowed are long enough.
                let active_len = cmp::min(length, buffer.len());

                // self.current_app.set(Some(processid));
                match command {
                    NonvolatileCommand::UserspaceRead => {
                        self.driver.read(buffer, physical_address, active_len)
                    }
                    NonvolatileCommand::UserspaceWrite => {
                        self.driver.write(buffer, physical_address, active_len)
                    }
                    _ => Err(ErrorCode::FAIL),
                }
            })
    }

    fn check_queue(&self) {
        // Check if there are any pending events.
        if self.kernel_pending_command.get() {
            self.kernel_buffer.take().map(|kernel_buffer| {
                self.kernel_pending_command.set(false);
                self.current_user.set(NonvolatileUser::Kernel);

                match self.kernel_command.get() {
                    NonvolatileCommand::KernelRead => self.driver.read(
                        kernel_buffer,
                        self.kernel_readwrite_address.get(),
                        self.kernel_readwrite_length.get(),
                    ),
                    NonvolatileCommand::KernelWrite => self.driver.write(
                        kernel_buffer,
                        self.kernel_readwrite_address.get(),
                        self.kernel_readwrite_length.get(),
                    ),
                    _ => Err(ErrorCode::FAIL),
                }
            });
        } else {
            // If the kernel is not requesting anything, check all of the apps.
            for cntr in self.apps.iter() {
                let processid = cntr.processid();
                let started_command = cntr.enter(|app, _| {
                    if app.pending_command {
                        app.pending_command = false;
                        self.current_user.set(NonvolatileUser::App {
                            processid: processid,
                        });
                        if let Ok(()) =
                            self.userspace_call_driver(app.command, app.offset, app.length)
                        {
                            true
                        } else {
                            false
                        }
                    } else {
                        false
                    }
                });
                if started_command {
                    break;
                }
            }
        }
    }
}

/// This is the callback client for the underlying physical storage driver.
impl hil::nonvolatile_storage::NonvolatileStorageClient for NonvolatileStorage<'_> {
    fn read_done(&self, buffer: &'static mut [u8], length: usize) {
        // Switch on which user of this capsule generated this callback.
        self.current_user.take().map(|user| {
            match user {
                NonvolatileUser::Kernel => {
                    self.kernel_client.map(move |client| {
                        client.read_done(buffer, length);
                    });
                }
                NonvolatileUser::App { processid } => {
                    let _ = self.apps.enter(processid, move |_, kernel_data| {
                        // Need to copy in the contents of the buffer
                        let _ = kernel_data
                            .get_readwrite_processbuffer(rw_allow::READ)
                            .and_then(|read| {
                                read.mut_enter(|app_buffer| {
                                    let read_len = cmp::min(app_buffer.len(), length);

                                    let d = &app_buffer[0..read_len];
                                    for (i, c) in buffer[0..read_len].iter().enumerate() {
                                        d[i].set(*c);
                                    }
                                })
                            });

                        // Replace the buffer we used to do this read.
                        self.buffer.replace(buffer);

                        // And then signal the app.
                        kernel_data
                            .schedule_upcall(upcall::READ_DONE, (length, 0, 0))
                            .ok();
                    });
                }
            }
        });

        self.check_queue();
    }

    fn write_done(&self, buffer: &'static mut [u8], length: usize) {
        // Switch on which user of this capsule generated this callback.
        self.current_user.take().map(|user| {
            match user {
                NonvolatileUser::Kernel => {
                    self.kernel_client.map(move |client| {
                        client.write_done(buffer, length);
                    });
                }
                NonvolatileUser::App { processid } => {
                    let _ = self.apps.enter(processid, move |_app, kernel_data| {
                        // Replace the buffer we used to do this write.
                        self.buffer.replace(buffer);

                        // And then signal the app.
                        kernel_data
                            .schedule_upcall(upcall::WRITE_DONE, (length, 0, 0))
                            .ok();
                    });
                }
            }
        });

        self.check_queue();
    }
}

/// Provide an interface for the kernel.
impl<'a> hil::nonvolatile_storage::NonvolatileStorage<'a> for NonvolatileStorage<'a> {
    fn set_client(&self, client: &'a dyn hil::nonvolatile_storage::NonvolatileStorageClient) {
        self.kernel_client.set(client);
    }

    fn read(
        &self,
        buffer: &'static mut [u8],
        address: usize,
        length: usize,
    ) -> Result<(), ErrorCode> {
        self.kernel_buffer.replace(buffer);
        self.enqueue_command(NonvolatileCommand::KernelRead, address, length, None)
    }

    fn write(
        &self,
        buffer: &'static mut [u8],
        address: usize,
        length: usize,
    ) -> Result<(), ErrorCode> {
        self.kernel_buffer.replace(buffer);
        self.enqueue_command(NonvolatileCommand::KernelWrite, address, length, None)
    }
}

/// Provide an interface for userland.
impl SyscallDriver for NonvolatileStorage<'_> {
    /// Command interface.
    ///
    /// Commands are selected by the lowest 8 bits of the first argument.
    ///
    /// ### `command_num`
    ///
    /// - `0`: Return Ok(()) if this driver is included on the platform.
    /// - `1`: Return the number of bytes available to userspace.
    /// - `2`: Start a read from the nonvolatile storage.
    /// - `3`: Start a write to the nonvolatile_storage.
    fn command(
        &self,
        command_num: usize,
        offset: usize,
        length: usize,
        processid: ProcessId,
    ) -> CommandReturn {
        match self.assign_app_region(processid) {
            Ok(()) => (),
            Err(e) => return CommandReturn::failure(e),
        }

        match command_num {
            0 => CommandReturn::success(),

            1 => {
                // How many bytes are accessible from userspace
                let res = self.apps.enter(processid, |app, _kernel_data| {
                    match &app.region {
                        Some(region) => Some(region.length),
                        None => None,
                    }
                });

                match res {
                    Ok(region_length) => match region_length {
                        // TODO: Would break on 64-bit platforms
                        Some(bytes) => CommandReturn::success_u32(bytes as u32),
                        None => CommandReturn::failure(ErrorCode::FAIL),
                    },
                    Err(_) => CommandReturn::failure(ErrorCode::FAIL),
                }
            }

            2 => {
                // Issue a read command
                let res = self.enqueue_command(
                    NonvolatileCommand::UserspaceRead,
                    offset,
                    length,
                    Some(processid),
                );

                match res {
                    Ok(()) => CommandReturn::success(),
                    Err(e) => CommandReturn::failure(e),
                }
            }

            3 => {
                // Issue a write command
                let res = self.enqueue_command(
                    NonvolatileCommand::UserspaceWrite,
                    offset,
                    length,
                    Some(processid),
                );

                match res {
                    Ok(()) => CommandReturn::success(),
                    Err(e) => CommandReturn::failure(e),
                }
            }

            _ => CommandReturn::failure(ErrorCode::NOSUPPORT),
        }
    }

    fn allocate_grant(&self, processid: ProcessId) -> Result<(), kernel::process::Error> {
        self.apps.enter(processid, |_, _| {})
    }
}
