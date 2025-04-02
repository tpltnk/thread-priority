//! This module defines the windows thread control.
//!
//! The crate's prelude doesn't have much control over
//! the windows threads, and this module provides
//! better control over those.

use winapi::ctypes::c_int;
use winapi::shared::minwindef::DWORD;
use winapi::um::errhandlingapi::GetLastError;
use winapi::um::processthreadsapi::{
    GetCurrentProcess, GetCurrentThread, GetThreadPriority, SetPriorityClass, SetProcessPriorityBoost, SetThreadIdealProcessor, SetThreadPriority, SetThreadPriorityBoost
};
use winapi::um::winbase;
use winapi::um::winnt::HANDLE;

use crate::{Error, ThreadPriority};

/// An alias type for specifying the ideal processor.
/// Used in the WinAPI for affinity control.
pub type IdealProcessor = DWORD;

/// An alias type for a thread id.
pub type ThreadId = HANDLE;

/// The WinAPI priority representation. Check out MSDN for more info:
/// <https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-setthreadpriority>
#[repr(u32)]
#[derive(Debug, Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub enum WinAPIThreadPriority {
    /// Begin background processing mode. The system lowers the resource
    /// scheduling priorities of the thread so that it can perform background
    /// work without significantly affecting activity in the foreground.
    ///
    /// This value can be specified only if hThread is a handle to the current
    /// thread. The function fails if the thread is already in background processing mode.
    ///
    /// # Warning
    /// Windows Server 2003: This value is not supported.
    BackgroundModeBegin = winbase::THREAD_MODE_BACKGROUND_BEGIN,
    /// End background processing mode. The system restores the resource
    /// scheduling priorities of the thread as they were before the thread
    /// entered background processing mode.
    ///
    /// This value can be specified only if hThread is a handle to the current thread.
    /// The function fails if the thread is not in background processing mode.
    ///
    /// # Warning
    /// Windows Server 2003: This value is not supported.
    BackgroundModeEnd = winbase::THREAD_MODE_BACKGROUND_END,
    /// Priority 1 point above the priority class.
    AboveNormal = winbase::THREAD_PRIORITY_ABOVE_NORMAL,
    /// Priority 1 point below the priority class.
    BelowNormal = winbase::THREAD_PRIORITY_BELOW_NORMAL,
    /// Priority 2 points above the priority class.
    Highest = winbase::THREAD_PRIORITY_HIGHEST,
    /// Base priority of 1 for IDLE_PRIORITY_CLASS, BELOW_NORMAL_PRIORITY_CLASS,
    /// NORMAL_PRIORITY_CLASS, ABOVE_NORMAL_PRIORITY_CLASS, or HIGH_PRIORITY_CLASS
    /// processes, and a base priority of 16 for REALTIME_PRIORITY_CLASS processes.
    Idle = winbase::THREAD_PRIORITY_IDLE,
    /// Priority 2 points below the priority class.
    Lowest = winbase::THREAD_PRIORITY_LOWEST,
    /// Normal priority for the priority class.
    Normal = winbase::THREAD_PRIORITY_NORMAL,
    /// Base priority of 15 for IDLE_PRIORITY_CLASS, BELOW_NORMAL_PRIORITY_CLASS,
    /// NORMAL_PRIORITY_CLASS, ABOVE_NORMAL_PRIORITY_CLASS, or HIGH_PRIORITY_CLASS
    /// processes, and a base priority of 31 for REALTIME_PRIORITY_CLASS processes.
    TimeCritical = winbase::THREAD_PRIORITY_TIME_CRITICAL,
}

impl std::convert::TryFrom<ThreadPriority> for WinAPIThreadPriority {
    type Error = crate::Error;

    fn try_from(priority: ThreadPriority) -> Result<Self, Self::Error> {
        Ok(match priority {
            ThreadPriority::Min => WinAPIThreadPriority::Lowest,
            ThreadPriority::Crossplatform(crate::ThreadPriorityValue(p)) => match p {
                0 => WinAPIThreadPriority::Idle,
                1..=19 => WinAPIThreadPriority::Lowest,
                21..=39 => WinAPIThreadPriority::BelowNormal,
                41..=59 => WinAPIThreadPriority::Normal,
                61..=79 => WinAPIThreadPriority::AboveNormal,
                81..=98 => WinAPIThreadPriority::Highest,
                99 => WinAPIThreadPriority::TimeCritical,
                _ => return Err(Error::Priority("The value is out of range [0; 99].")),
            },
            ThreadPriority::Os(crate::ThreadPriorityOsValue(p)) => match p {
                winbase::THREAD_MODE_BACKGROUND_BEGIN => WinAPIThreadPriority::BackgroundModeBegin,
                winbase::THREAD_MODE_BACKGROUND_END => WinAPIThreadPriority::BackgroundModeEnd,
                winbase::THREAD_PRIORITY_ABOVE_NORMAL => WinAPIThreadPriority::AboveNormal,
                winbase::THREAD_PRIORITY_BELOW_NORMAL => WinAPIThreadPriority::BelowNormal,
                winbase::THREAD_PRIORITY_HIGHEST => WinAPIThreadPriority::Highest,
                winbase::THREAD_PRIORITY_IDLE => WinAPIThreadPriority::Idle,
                winbase::THREAD_PRIORITY_LOWEST => WinAPIThreadPriority::Lowest,
                winbase::THREAD_PRIORITY_NORMAL => WinAPIThreadPriority::Normal,
                winbase::THREAD_PRIORITY_TIME_CRITICAL => WinAPIThreadPriority::TimeCritical,
                _ => {
                    return Err(Error::Priority(
                        "The value is out of range of allowed values.",
                    ))
                }
            },
            ThreadPriority::Max => WinAPIThreadPriority::Highest,
        })
    }
}

impl std::convert::TryFrom<DWORD> for WinAPIThreadPriority {
    type Error = crate::Error;

    fn try_from(priority: DWORD) -> Result<Self, Self::Error> {
        Ok(match priority {
            winbase::THREAD_MODE_BACKGROUND_BEGIN => WinAPIThreadPriority::BackgroundModeBegin,
            winbase::THREAD_MODE_BACKGROUND_END => WinAPIThreadPriority::BackgroundModeEnd,
            winbase::THREAD_PRIORITY_ABOVE_NORMAL => WinAPIThreadPriority::AboveNormal,
            winbase::THREAD_PRIORITY_BELOW_NORMAL => WinAPIThreadPriority::BelowNormal,
            winbase::THREAD_PRIORITY_HIGHEST => WinAPIThreadPriority::Highest,
            winbase::THREAD_PRIORITY_IDLE => WinAPIThreadPriority::Idle,
            winbase::THREAD_PRIORITY_LOWEST => WinAPIThreadPriority::Lowest,
            winbase::THREAD_PRIORITY_NORMAL => WinAPIThreadPriority::Normal,
            winbase::THREAD_PRIORITY_TIME_CRITICAL => WinAPIThreadPriority::TimeCritical,
            _ => return Err(Error::Priority("Priority couldn't be parsed")),
        })
    }
}

impl From<WinAPIThreadPriority> for crate::ThreadPriorityOsValue {
    fn from(p: WinAPIThreadPriority) -> Self {
        crate::ThreadPriorityOsValue(p as u32)
    }
}

/// Sets thread's priority and schedule policy.
///
/// * May require privileges
///
/// # Usage
///
/// Setting thread priority to minimum:
///
/// ```rust
/// use thread_priority::*;
///
/// let thread_id = thread_native_id();
/// assert!(set_thread_priority(thread_id, ThreadPriority::Min).is_ok());
/// ```
///
/// If there's an error, a result of
/// [`GetLastError`](https://docs.microsoft.com/en-us/windows/win32/api/errhandlingapi/nf-errhandlingapi-getlasterror) is returned.
pub fn set_thread_priority(native: ThreadId, priority: ThreadPriority) -> Result<(), Error> {
    set_winapi_thread_priority(native, WinAPIThreadPriority::try_from(priority)?)
}

/// Sets thread's priority and schedule policy using WinAPI priority values.
///
/// * May require privileges
///
/// # Usage
///
/// Setting thread priority to minimum:
///
/// ```rust
/// use thread_priority::*;
///
/// let thread_id = thread_native_id();
/// assert!(set_winapi_thread_priority(thread_id, WinAPIThreadPriority::Normal).is_ok());
/// ```
///
/// If there's an error, a result of
/// [`GetLastError`](https://docs.microsoft.com/en-us/windows/win32/api/errhandlingapi/nf-errhandlingapi-getlasterror) is returned.
pub fn set_winapi_thread_priority(
    native: ThreadId,
    priority: WinAPIThreadPriority,
) -> Result<(), Error> {
    unsafe {
        if SetThreadPriority(native, priority as c_int) != 0 {
            Ok(())
        } else {
            Err(Error::OS(GetLastError() as i32))
        }
    }
}

/// Set current thread's priority.
///
/// * May require privileges
///
/// # Usage
///
/// Setting thread priority to minimum:
///
/// ```rust
/// use thread_priority::*;
///
/// assert!(set_current_thread_priority(ThreadPriority::Min).is_ok());
/// assert!(set_current_thread_priority(ThreadPriority::Os(WinAPIThreadPriority::Lowest.into())).is_ok());
/// ```
///
/// If there's an error, a result of
/// [`GetLastError`](https://docs.microsoft.com/en-us/windows/win32/api/errhandlingapi/nf-errhandlingapi-getlasterror) is returned.

pub fn set_current_thread_priority(priority: ThreadPriority) -> Result<(), Error> {
    let thread_id = thread_native_id();
    set_thread_priority(thread_id, priority)
}

/// Get the thread's priority value.
///
/// Returns current thread's priority.
///
/// # Usage
///
/// ```rust
/// use thread_priority::{thread_native_id, get_thread_priority};
///
/// assert!(get_thread_priority(thread_native_id()).is_ok());
/// ```
pub fn get_thread_priority(native: ThreadId) -> Result<ThreadPriority, Error> {
    unsafe {
        let ret = GetThreadPriority(native);
        if ret as u32 != winbase::THREAD_PRIORITY_ERROR_RETURN {
            Ok(ThreadPriority::Os(crate::ThreadPriorityOsValue(
                WinAPIThreadPriority::try_from(ret as DWORD)? as u32,
            )))
        } else {
            Err(Error::OS(GetLastError() as i32))
        }
    }
}

/// Get current thread's priority value.
///
/// Returns current thread's priority.
///
/// # Usage
///
/// ```rust
/// use thread_priority::get_current_thread_priority;
///
/// assert!(get_current_thread_priority().is_ok());
/// ```
pub fn get_current_thread_priority() -> Result<ThreadPriority, Error> {
    unsafe {
        let ret = GetThreadPriority(thread_native_id());
        if ret as u32 != winbase::THREAD_PRIORITY_ERROR_RETURN {
            Ok(ThreadPriority::Os(crate::ThreadPriorityOsValue(
                WinAPIThreadPriority::try_from(ret as DWORD)? as u32,
            )))
        } else {
            Err(Error::OS(GetLastError() as i32))
        }
    }
}

/// Returns current thread id, which is the current OS's native handle.
/// It may or may not be equal or even related to rust's thread id,
/// there is absolutely no guarantee for that.
///
/// # Usage
///
/// ```rust
/// use thread_priority::thread_native_id;
///
/// assert!(!thread_native_id().is_null());
/// ```
pub fn thread_native_id() -> ThreadId {
    unsafe { GetCurrentThread() }
}

/// Disables or enables the ability of the system to temporarily boost the priority of a thread.
///
/// If there's an error, a result of
/// [`GetLastError`](https://docs.microsoft.com/en-us/windows/win32/api/errhandlingapi/nf-errhandlingapi-getlasterror) is returned.
///
/// # Usage
///
/// ```rust
/// use thread_priority::*;
///
/// let thread_id = thread_native_id();
/// assert!(set_thread_priority_boost(thread_id, false).is_ok())
/// ```
pub fn set_thread_priority_boost(native: ThreadId, enabled: bool) -> Result<(), Error> {
    unsafe {
        if SetThreadPriorityBoost(native, enabled as i32) != 0 {
            Ok(())
        } else {
            Err(Error::OS(GetLastError() as i32))
        }
    }
}

/// Disables or enables the ability of the system to temporarily boost the priority of a current thread.
///
/// If there's an error, a result of
/// [`GetLastError`](https://docs.microsoft.com/en-us/windows/win32/api/errhandlingapi/nf-errhandlingapi-getlasterror) is returned.
///
/// This is a short-hand of the `set_thread_priority_boost` function for the current thread.
pub fn set_current_thread_priority_boost(enabled: bool) -> Result<(), Error> {
    set_thread_priority_boost(thread_native_id(), enabled)
}

/// Sets a preferred processor for a thread. The system schedules threads on their preferred
/// processors whenever possible.
///
/// On a system with more than 64 processors, this function sets the preferred processor to a
/// logical processor in the processor group to which the calling thread is assigned. Use the
/// `SetThreadIdealProcessorEx` function to specify a processor group and preferred processor.
///
/// If there's an error, a result of
/// [`GetLastError`](https://docs.microsoft.com/en-us/windows/win32/api/errhandlingapi/nf-errhandlingapi-getlasterror) is returned.
/// On success, the function returns a previously assigned processor.
///
/// # Note
/// The processor number starts with zero.
///
/// # Usage
///
/// ```rust
/// use thread_priority::*;
///
/// let thread_id = thread_native_id();
/// assert!(set_thread_ideal_processor(thread_id, 0).is_ok())
/// ```
pub fn set_thread_ideal_processor(
    native: ThreadId,
    ideal_processor: IdealProcessor,
) -> Result<IdealProcessor, Error> {
    unsafe {
        let ret = SetThreadIdealProcessor(native, ideal_processor);
        if ret == IdealProcessor::max_value() - 1 {
            Err(Error::OS(GetLastError() as i32))
        } else {
            Ok(ret)
        }
    }
}

/// Sets a preferred processor for a current thread. The system schedules threads on their preferred
/// processors whenever possible.
///
/// This is a short-hand of the `set_thread_ideal_processor` function for the current thread.
pub fn set_current_thread_ideal_processor(
    ideal_processor: IdealProcessor,
) -> Result<IdealProcessor, Error> {
    set_thread_ideal_processor(thread_native_id(), ideal_processor)
}

impl std::convert::TryFrom<u32> for crate::ThreadPriorityOsValue {
    type Error = ();

    fn try_from(value: u32) -> Result<Self, Self::Error> {
        Ok(crate::ThreadPriorityOsValue(match value {
            winbase::THREAD_MODE_BACKGROUND_BEGIN
            | winbase::THREAD_MODE_BACKGROUND_END
            | winbase::THREAD_PRIORITY_ABOVE_NORMAL
            | winbase::THREAD_PRIORITY_BELOW_NORMAL
            | winbase::THREAD_PRIORITY_HIGHEST
            | winbase::THREAD_PRIORITY_IDLE
            | winbase::THREAD_PRIORITY_LOWEST
            | winbase::THREAD_PRIORITY_NORMAL
            | winbase::THREAD_PRIORITY_TIME_CRITICAL => value,
            _ => return Err(()),
        }))
    }
}

/// Alias for native process ID.
pub type ProcessId = HANDLE;

/// Gets current process handle.
pub fn process_native_id() -> ProcessId {
    unsafe { GetCurrentProcess() }
}

/// WinAPI process priority class representation.
/// <https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-setpriorityclass>
#[repr(u32)]
#[derive(Debug, Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub enum WinAPIProcessPriorityClass {
    /// Begin background processing mode.
    /// The system lowers the resource scheduling priorities of the process (and its threads) so that it can perform background work without significantly affecting activity in the foreground.
    /// This value can be specified only if hProcess is a handle to the current process. The function fails if the process is already in background processing mode.
    ///
    /// # Warning
    /// Windows Server 2003 and Windows XP: This value is not supported.
    BackgroundBegin = winbase::PROCESS_MODE_BACKGROUND_BEGIN,
    /// End background processing mode.
    /// The system restores the resource scheduling priorities of the process (and its threads) as they were before the process entered background processing mode.
    /// This value can be specified only if hProcess is a handle to the current process. The function fails if the process is not in background processing mode.
    ///
    /// # Warning
    /// Windows Server 2003 and Windows XP:  This value is not supported.
    BackgroundEnd = winbase::PROCESS_MODE_BACKGROUND_END,
    /// Process that has priority above NORMAL_PRIORITY_CLASS but below HIGH_PRIORITY_CLASS.
    AboveNormal = winbase::ABOVE_NORMAL_PRIORITY_CLASS,
    /// Process that has priority above IDLE_PRIORITY_CLASS but below NORMAL_PRIORITY_CLASS.
    BelowNormal = winbase::BELOW_NORMAL_PRIORITY_CLASS,
    /// Process that performs time-critical tasks that must be executed immediately.
    /// The threads of the process preempt the threads of normal or idle priority class processes.
    /// An example is the Task List, which must respond quickly when called by the user, regardless of the load on the operating system.
    /// Use extreme care when using the high-priority class, because a high-priority class application can use nearly all available CPU time.
    High = winbase::HIGH_PRIORITY_CLASS,
    /// Process whose threads run only when the system is idle.
    /// The threads of the process are preempted by the threads of any process running in a higher priority class. An example is a screen saver.
    /// The idle-priority class is inherited by child processes.
    Idle = winbase::IDLE_PRIORITY_CLASS,
    /// Process with no special scheduling needs.
    Normal = winbase::NORMAL_PRIORITY_CLASS,
    /// Process that has the highest possible priority.
    /// The threads of the process preempt the threads of all other processes, including operating system processes performing important tasks.
    /// For example, a real-time process that executes for more than a very brief interval can cause disk caches not to flush or cause the mouse to be unresponsive.
    Realtime = winbase::REALTIME_PRIORITY_CLASS,
}

/// Disables or enables the ability of the system to temporarily boost the priority of the threads of the specified process.
///
/// # Usage
/// 
/// ```rust
/// use thread_priority::*;
/// 
/// let process_id = process_native_id();
/// assert!(set_process_priority_boost(process_id, true).is_ok());
/// ```
pub fn set_process_priority_boost(native: ProcessId, enabled: bool) -> Result<(), Error> {
    unsafe {
        if SetProcessPriorityBoost(native, enabled as i32) != 0 {
            Ok(())
        } else {
            Err(Error::OS(GetLastError() as i32))
        }
    }
}

/// Like [`set_process_priority_boost`] but for current process.
pub fn set_current_process_priority_boost(enabled: bool) -> Result<(), Error> {
    set_process_priority_boost(process_native_id(), enabled)
}

/// Sets priority class for a process.
/// 
/// # Usage
/// 
/// ```rust
/// use thread_priority::*;
/// 
/// let process_id = process_native_id();
/// assert!(set_process_priority_class(process_id, WinAPIProcessPriorityClass::Normal).is_ok());
/// ```
pub fn set_process_priority_class(
    native: ProcessId,
    class: WinAPIProcessPriorityClass,
) -> Result<(), Error> {
    unsafe {
        if SetPriorityClass(native, class as u32) != 0 {
            Ok(())
        } else {
            Err(Error::OS(GetLastError() as i32))
        }
    }
}

/// Sets current process' priority class.
///
/// If there's an error, a result of
/// [`GetLastError`](https://docs.microsoft.com/en-us/windows/win32/api/errhandlingapi/nf-errhandlingapi-getlasterror) is returned.
///
/// This is a short-hand of the `set_process_priority_class` function for the current thread.
pub fn set_current_process_priority_class(class: WinAPIProcessPriorityClass) -> Result<(), Error> {
    set_process_priority_class(process_native_id(), class)
}

/// Windows-specific complemented part of the [`crate::ThreadExt`] trait.
pub trait ThreadExt {
    /// Returns current thread's priority.
    /// For more info see [`thread_priority`].
    ///
    /// ```rust
    /// use thread_priority::*;
    ///
    /// assert!(std::thread::current().get_priority().is_ok());
    /// ```
    fn get_priority(&self) -> Result<ThreadPriority, Error> {
        get_current_thread_priority()
    }

    /// Sets current thread's priority.
    /// For more info see [`set_current_thread_priority`].
    ///
    /// ```rust
    /// use thread_priority::*;
    ///
    /// assert!(std::thread::current().set_priority(ThreadPriority::Min).is_ok());
    /// ```
    fn set_priority(&self, priority: ThreadPriority) -> Result<(), Error> {
        set_current_thread_priority(priority)
    }

    /// Returns current thread's windows id.
    /// For more info see [`thread_native_id`].
    ///
    /// ```rust
    /// use thread_priority::*;
    ///
    /// assert!(!std::thread::current().get_native_id().unwrap().is_null());
    /// ```
    fn get_native_id(&self) -> Result<ThreadId, Error>;

    /// Sets current thread's ideal processor.
    /// For more info see [`set_current_thread_ideal_processor`].
    ///
    /// ```rust
    /// use thread_priority::*;
    ///
    /// assert!(std::thread::current().set_ideal_processor(0).is_ok());
    /// ```
    fn set_ideal_processor(
        &self,
        ideal_processor: IdealProcessor,
    ) -> Result<IdealProcessor, Error> {
        set_current_thread_ideal_processor(ideal_processor)
    }

    /// Sets current thread's priority boost.
    /// For more info see [`set_current_thread_priority_boost`].
    ///
    /// ```rust
    /// use thread_priority::*;
    ///
    /// assert!(std::thread::current().set_priority_boost(true).is_ok());
    /// ```
    fn set_priority_boost(&self, enabled: bool) -> Result<(), Error> {
        set_current_thread_priority_boost(enabled)
    }
}

/// Auto-implementation of this trait for the [`std::thread::Thread`].
impl ThreadExt for std::thread::Thread {
    fn get_native_id(&self) -> Result<ThreadId, Error> {
        if self.id() == std::thread::current().id() {
            Ok(thread_native_id())
        } else {
            Err(Error::Priority("The `ThreadExt::get_native_id()` is currently limited to be called on the current thread."))
        }
    }
}
