#![forbid(unsafe_code)]

//! Comprehensive POSIX process, signal, time, memory-mapping, and environment procedures.

use crate::{SimProcedure, SimResult, SimState};
use super::heap::TrackedHeap;

// ---------------------------------------------------------------------------
// Process & User IDs
// ---------------------------------------------------------------------------

/// `getpid(void)`
pub struct GetpidProcedure;

impl SimProcedure for GetpidProcedure {
    fn name(&self) -> &'static str {
        "getpid"
    }

    fn apply(&self, _state: &SimState) -> SimResult {
        SimResult::Return(1000)
    }
}

/// `getppid(void)`
pub struct GetppidProcedure;

impl SimProcedure for GetppidProcedure {
    fn name(&self) -> &'static str {
        "getppid"
    }

    fn apply(&self, _state: &SimState) -> SimResult {
        SimResult::Return(999)
    }
}

/// `getuid(void)`
pub struct GetuidProcedure;

impl SimProcedure for GetuidProcedure {
    fn name(&self) -> &'static str {
        "getuid"
    }

    fn apply(&self, _state: &SimState) -> SimResult {
        SimResult::Return(1000)
    }
}

/// `geteuid(void)`
pub struct GeteuidProcedure;

impl SimProcedure for GeteuidProcedure {
    fn name(&self) -> &'static str {
        "geteuid"
    }

    fn apply(&self, _state: &SimState) -> SimResult {
        SimResult::Return(1000)
    }
}

/// `getgid(void)`
pub struct GetgidProcedure;

impl SimProcedure for GetgidProcedure {
    fn name(&self) -> &'static str {
        "getgid"
    }

    fn apply(&self, _state: &SimState) -> SimResult {
        SimResult::Return(1000)
    }
}

/// `getegid(void)`
pub struct GetegidProcedure;

impl SimProcedure for GetegidProcedure {
    fn name(&self) -> &'static str {
        "getegid"
    }

    fn apply(&self, _state: &SimState) -> SimResult {
        SimResult::Return(1000)
    }
}

/// `fork(void)`: returns simulated child PID.
pub struct ForkProcedure;

impl SimProcedure for ForkProcedure {
    fn name(&self) -> &'static str {
        "fork"
    }

    fn apply(&self, _state: &SimState) -> SimResult {
        SimResult::Return(1001)
    }
}

/// `waitpid(pid_t pid, int *wstatus, int options)`
pub struct WaitpidProcedure;

impl SimProcedure for WaitpidProcedure {
    fn name(&self) -> &'static str {
        "waitpid"
    }

    fn apply(&self, state: &SimState) -> SimResult {
        let pid = state.get_arg(0);
        let status_ptr = state.get_arg(1);

        if status_ptr != 0 {
            let mut next = state.clone();
            next.write_memory(status_ptr, 0u32.to_le_bytes().to_vec());
            next.return_value = Some(pid);
            next.set_reg(0, pid);
            SimResult::Continue(next)
        } else {
            SimResult::Return(pid)
        }
    }
}

/// `execve(const char *filename, char *const argv[], char *const envp[])`
pub struct ExecveProcedure;

impl SimProcedure for ExecveProcedure {
    fn name(&self) -> &'static str {
        "execve"
    }

    fn apply(&self, _state: &SimState) -> SimResult {
        SimResult::Return(0)
    }
}

/// `exit(int status)`
pub struct ExitProcedure;

impl SimProcedure for ExitProcedure {
    fn name(&self) -> &'static str {
        "exit"
    }

    fn apply(&self, _state: &SimState) -> SimResult {
        SimResult::Exit
    }
}

/// `abort(void)`
pub struct AbortProcedure;

impl SimProcedure for AbortProcedure {
    fn name(&self) -> &'static str {
        "abort"
    }

    fn apply(&self, _state: &SimState) -> SimResult {
        SimResult::Exit
    }
}

// ---------------------------------------------------------------------------
// Signals & Process Control
// ---------------------------------------------------------------------------

/// `kill(pid_t pid, int sig)`
pub struct KillProcedure;

impl SimProcedure for KillProcedure {
    fn name(&self) -> &'static str {
        "kill"
    }

    fn apply(&self, _state: &SimState) -> SimResult {
        SimResult::Return(0)
    }
}

/// `raise(int sig)`
pub struct RaiseProcedure;

impl SimProcedure for RaiseProcedure {
    fn name(&self) -> &'static str {
        "raise"
    }

    fn apply(&self, _state: &SimState) -> SimResult {
        SimResult::Return(0)
    }
}

/// `sigaction(int signum, const struct sigaction *act, struct sigaction *oldact)`
pub struct SigactionProcedure;

impl SimProcedure for SigactionProcedure {
    fn name(&self) -> &'static str {
        "sigaction"
    }

    fn apply(&self, _state: &SimState) -> SimResult {
        SimResult::Return(0)
    }
}

/// `signal(int signum, sighandler_t handler)`
pub struct SignalProcedure;

impl SimProcedure for SignalProcedure {
    fn name(&self) -> &'static str {
        "signal"
    }

    fn apply(&self, _state: &SimState) -> SimResult {
        SimResult::Return(0)
    }
}

// ---------------------------------------------------------------------------
// Time & Sleep
// ---------------------------------------------------------------------------

/// `time(time_t *tloc)`
pub struct TimeProcedure;

impl SimProcedure for TimeProcedure {
    fn name(&self) -> &'static str {
        "time"
    }

    fn apply(&self, state: &SimState) -> SimResult {
        let tloc = state.get_arg(0);
        let timestamp = 1700000000u64; // deterministic epoch timestamp

        if tloc != 0 {
            let mut next = state.clone();
            next.write_memory(tloc, timestamp.to_le_bytes().to_vec());
            next.return_value = Some(timestamp);
            next.set_reg(0, timestamp);
            SimResult::Continue(next)
        } else {
            SimResult::Return(timestamp)
        }
    }
}

/// `gettimeofday(struct timeval *tv, struct timezone *tz)`
pub struct GettimeofdayProcedure;

impl SimProcedure for GettimeofdayProcedure {
    fn name(&self) -> &'static str {
        "gettimeofday"
    }

    fn apply(&self, state: &SimState) -> SimResult {
        let tv = state.get_arg(0);
        if tv != 0 {
            let mut buf = vec![0u8; 16]; // 8 bytes sec, 8 bytes usec
            buf[..8].copy_from_slice(&1700000000u64.to_le_bytes());
            buf[8..].copy_from_slice(&500000u64.to_le_bytes());

            let mut next = state.clone();
            next.write_memory(tv, buf);
            next.return_value = Some(0);
            next.set_reg(0, 0);
            SimResult::Continue(next)
        } else {
            SimResult::Return(0)
        }
    }
}

/// `nanosleep(const struct timespec *req, struct timespec *rem)`
pub struct NanosleepProcedure;

impl SimProcedure for NanosleepProcedure {
    fn name(&self) -> &'static str {
        "nanosleep"
    }

    fn apply(&self, _state: &SimState) -> SimResult {
        SimResult::Return(0)
    }
}

/// `sleep(unsigned int seconds)`
pub struct SleepProcedure;

impl SimProcedure for SleepProcedure {
    fn name(&self) -> &'static str {
        "sleep"
    }

    fn apply(&self, _state: &SimState) -> SimResult {
        SimResult::Return(0)
    }
}

// ---------------------------------------------------------------------------
// System Information & Memory Mapping
// ---------------------------------------------------------------------------

/// `uname(struct utsname *buf)`
pub struct UnameProcedure;

impl SimProcedure for UnameProcedure {
    fn name(&self) -> &'static str {
        "uname"
    }

    fn apply(&self, state: &SimState) -> SimResult {
        let buf = state.get_arg(0);
        // struct utsname has 5 65-byte char fields: sysname, nodename, release, version, machine
        let mut uts = vec![0u8; 5 * 65];

        let sysname = b"Linux\0";
        uts[0..sysname.len()].copy_from_slice(sysname);

        let nodename = b"angryier-sandbox\0";
        uts[65..65 + nodename.len()].copy_from_slice(nodename);

        let release = b"6.1.0-kp15\0";
        uts[130..130 + release.len()].copy_from_slice(release);

        let version = b"#1 SMP PREEMPT\0";
        uts[195..195 + version.len()].copy_from_slice(version);

        let machine = b"x86_64\0";
        uts[260..260 + machine.len()].copy_from_slice(machine);

        let mut next = state.clone();
        next.write_memory(buf, uts);
        next.return_value = Some(0);
        next.set_reg(0, 0);
        SimResult::Continue(next)
    }
}

/// `mmap(void *addr, size_t length, int prot, int flags, int fd, off_t offset)`
pub struct MmapProcedure {
    heap: TrackedHeap,
}

impl MmapProcedure {
    pub fn new(heap: TrackedHeap) -> Self {
        Self { heap }
    }
}

impl SimProcedure for MmapProcedure {
    fn name(&self) -> &'static str {
        "mmap"
    }

    fn apply(&self, state: &SimState) -> SimResult {
        let length = state.get_arg(1);
        let ptr = self.heap.allocate(length);
        SimResult::Return(ptr)
    }
}

/// `munmap(void *addr, size_t length)`
pub struct MunmapProcedure {
    heap: TrackedHeap,
}

impl MunmapProcedure {
    pub fn new(heap: TrackedHeap) -> Self {
        Self { heap }
    }
}

impl SimProcedure for MunmapProcedure {
    fn name(&self) -> &'static str {
        "munmap"
    }

    fn apply(&self, state: &SimState) -> SimResult {
        let addr = state.get_arg(0);
        let _ = self.heap.deallocate(addr);
        SimResult::Return(0)
    }
}

/// `mprotect(void *addr, size_t len, int prot)`
pub struct MprotectProcedure;

impl SimProcedure for MprotectProcedure {
    fn name(&self) -> &'static str {
        "mprotect"
    }

    fn apply(&self, _state: &SimState) -> SimResult {
        SimResult::Return(0)
    }
}

/// `sched_yield(void)`
pub struct SchedYieldProcedure;

impl SimProcedure for SchedYieldProcedure {
    fn name(&self) -> &'static str {
        "sched_yield"
    }

    fn apply(&self, _state: &SimState) -> SimResult {
        SimResult::Return(0)
    }
}

// ---------------------------------------------------------------------------
// Environment & Utilities
// ---------------------------------------------------------------------------

/// `getenv(const char *name)`
pub struct GetenvProcedure;

impl SimProcedure for GetenvProcedure {
    fn name(&self) -> &'static str {
        "getenv"
    }

    fn apply(&self, _state: &SimState) -> SimResult {
        SimResult::Return(0) // Null pointer: environment variable not set
    }
}

/// `rand(void)`
pub struct RandProcedure;

impl SimProcedure for RandProcedure {
    fn name(&self) -> &'static str {
        "rand"
    }

    fn apply(&self, _state: &SimState) -> SimResult {
        SimResult::Return(42) // Deterministic random seed
    }
}

/// `srand(unsigned int seed)`
pub struct SrandProcedure;

impl SimProcedure for SrandProcedure {
    fn name(&self) -> &'static str {
        "srand"
    }

    fn apply(&self, _state: &SimState) -> SimResult {
        SimResult::Return(0)
    }
}

/// `abs(int j)`
pub struct AbsProcedure;

impl SimProcedure for AbsProcedure {
    fn name(&self) -> &'static str {
        "abs"
    }

    fn apply(&self, state: &SimState) -> SimResult {
        let j = state.get_arg(0) as i32;
        let res = j.abs();
        SimResult::Return(res as u32 as u64)
    }
}

/// `labs(long int j)`
pub struct LabsProcedure;

impl SimProcedure for LabsProcedure {
    fn name(&self) -> &'static str {
        "labs"
    }

    fn apply(&self, state: &SimState) -> SimResult {
        let j = state.get_arg(0) as i64;
        let res = j.abs();
        SimResult::Return(res as u64)
    }
}
