//! Keeps everything a program starts together, so kv can kill all of it: a
//! process group on Unix, a job object on Windows.

use std::io;

use tokio::process::{Child, Command};

/// Call before spawning: starts the program in its own process group, and
/// on Windows without a console window.
pub fn isolate(command: &mut Command) {
    #[cfg(unix)]
    command.process_group(0);
    #[cfg(windows)]
    {
        use windows_sys::Win32::System::Threading::{CREATE_NEW_PROCESS_GROUP, CREATE_NO_WINDOW};
        command.creation_flags(CREATE_NEW_PROCESS_GROUP | CREATE_NO_WINDOW);
    }
}

/// A started program and everything it starts. Dropping it kills them all.
pub struct ProcessTree {
    #[cfg(unix)]
    group: rustix::process::Pid,
    #[cfg(windows)]
    job: windows_sys::Win32::Foundation::HANDLE,
}

// SAFETY: the job handle is only used through thread-safe Win32 calls.
#[cfg(windows)]
unsafe impl Send for ProcessTree {}
#[cfg(windows)]
unsafe impl Sync for ProcessTree {}

impl ProcessTree {
    /// Takes charge of a child started after `isolate`. On Windows,
    /// processes the child starts before this call are not covered.
    pub fn adopt(child: &Child) -> io::Result<Self> {
        #[cfg(unix)]
        {
            let pid = child
                .id()
                .and_then(|id| rustix::process::Pid::from_raw(id as i32))
                .ok_or_else(|| io::Error::other("the program has already exited"))?;
            Ok(Self { group: pid })
        }
        #[cfg(windows)]
        {
            windows::adopt(child)
        }
    }

    /// Kills every process in the tree. Safe to call more than once.
    pub fn kill(&self) {
        #[cfg(unix)]
        {
            let _ = rustix::process::kill_process_group(self.group, rustix::process::Signal::KILL);
        }
        #[cfg(windows)]
        windows::terminate(self.job);
    }
}

impl Drop for ProcessTree {
    fn drop(&mut self) {
        self.kill();
        #[cfg(windows)]
        windows::close(self.job);
    }
}

#[cfg(windows)]
mod windows {
    use std::io;

    use tokio::process::Child;
    use windows_sys::Win32::Foundation::{CloseHandle, HANDLE};
    use windows_sys::Win32::System::JobObjects::{
        AssignProcessToJobObject, CreateJobObjectW, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
        JOBOBJECT_EXTENDED_LIMIT_INFORMATION, JobObjectExtendedLimitInformation,
        SetInformationJobObject, TerminateJobObject,
    };

    use super::ProcessTree;

    pub fn adopt(child: &Child) -> io::Result<ProcessTree> {
        let process = child
            .raw_handle()
            .ok_or_else(|| io::Error::other("the program has already exited"))?;
        // SAFETY: plain Win32 calls on handles we own or that the child
        // keeps open; the job handle is closed on every failure path.
        unsafe {
            let job = CreateJobObjectW(std::ptr::null(), std::ptr::null());
            if job.is_null() {
                return Err(io::Error::last_os_error());
            }
            let mut limits: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = std::mem::zeroed();
            limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
            let configured = SetInformationJobObject(
                job,
                JobObjectExtendedLimitInformation,
                (&limits as *const JOBOBJECT_EXTENDED_LIMIT_INFORMATION).cast(),
                size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
            );
            if configured == 0 || AssignProcessToJobObject(job, process as HANDLE) == 0 {
                let error = io::Error::last_os_error();
                CloseHandle(job);
                return Err(error);
            }
            Ok(ProcessTree { job })
        }
    }

    pub fn terminate(job: HANDLE) {
        // SAFETY: `job` stays open until `close`.
        unsafe { TerminateJobObject(job, 1) };
    }

    pub fn close(job: HANDLE) {
        // SAFETY: called once, from Drop.
        unsafe { CloseHandle(job) };
    }
}
