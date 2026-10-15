#![forbid(unsafe_code)]

//! Comprehensive POSIX file descriptor table, I/O, socket, and filesystem procedures.

use crate::{SimProcedure, SimResult, SimState};
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

/// Classification of a simulated file descriptor.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FdKind {
    Stdin,
    Stdout,
    Stderr,
    File { path: String, flags: u32, offset: u64 },
    Socket { domain: i32, sock_type: i32, protocol: i32, connected: bool },
    Pipe { read_end: bool, peer_fd: i32 },
    Epoll,
}

/// Simulated file descriptor entry.
#[derive(Clone, Debug)]
pub struct SimFd {
    pub fd: i32,
    pub kind: FdKind,
    pub buffer: Vec<u8>,
}

#[derive(Clone, Debug)]
pub struct SimFdTableState {
    pub fds: BTreeMap<i32, SimFd>,
    pub next_fd: i32,
}

impl Default for SimFdTableState {
    fn default() -> Self {
        let mut fds = BTreeMap::new();
        fds.insert(0, SimFd { fd: 0, kind: FdKind::Stdin, buffer: Vec::new() });
        fds.insert(1, SimFd { fd: 1, kind: FdKind::Stdout, buffer: Vec::new() });
        fds.insert(2, SimFd { fd: 2, kind: FdKind::Stderr, buffer: Vec::new() });
        Self { fds, next_fd: 3 }
    }
}

/// Thread-safe virtual file descriptor table.
#[derive(Clone, Debug, Default)]
pub struct SimFdTable {
    inner: Arc<Mutex<SimFdTableState>>,
}

impl SimFdTable {
    pub fn new() -> Self {
        Self::default()
    }

    /// Allocates a new file descriptor of the specified kind.
    pub fn alloc_fd(&self, kind: FdKind) -> i32 {
        let mut state = match self.inner.lock() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        };
        let fd = state.next_fd;
        state.next_fd = state.next_fd.saturating_add(1);
        state.fds.insert(fd, SimFd { fd, kind, buffer: Vec::new() });
        fd
    }

    /// Closes an open file descriptor. Returns 0 on success, -1 (EBADF) on error.
    pub fn close_fd(&self, fd: i32) -> i32 {
        let mut state = match self.inner.lock() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        };
        if state.fds.remove(&fd).is_some() {
            0
        } else {
            -1
        }
    }

    /// Checks if a file descriptor is open and valid.
    pub fn is_valid(&self, fd: i32) -> bool {
        let state = match self.inner.lock() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        };
        state.fds.contains_key(&fd)
    }
}

// ---------------------------------------------------------------------------
// SimProcedures
// ---------------------------------------------------------------------------

/// `open(const char *pathname, int flags, mode_t mode)`
pub struct OpenProcedure {
    table: SimFdTable,
}

impl OpenProcedure {
    pub fn new(table: SimFdTable) -> Self {
        Self { table }
    }
}

impl SimProcedure for OpenProcedure {
    fn name(&self) -> &'static str {
        "open"
    }

    fn apply(&self, state: &SimState) -> SimResult {
        let path_addr = state.get_arg(0);
        let flags = state.get_arg(1) as u32;
        let path_bytes = state.read_null_terminated_string(path_addr, 4096);
        let path = String::from_utf8_lossy(&path_bytes).into_owned();

        let fd = self.table.alloc_fd(FdKind::File {
            path,
            flags,
            offset: 0,
        });
        SimResult::Return(fd as u32 as u64)
    }
}

/// `close(int fd)`
pub struct CloseProcedure {
    table: SimFdTable,
}

impl CloseProcedure {
    pub fn new(table: SimFdTable) -> Self {
        Self { table }
    }
}

impl SimProcedure for CloseProcedure {
    fn name(&self) -> &'static str {
        "close"
    }

    fn apply(&self, state: &SimState) -> SimResult {
        let fd = state.get_arg(0) as i32;
        let res = self.table.close_fd(fd);
        SimResult::Return(res as u64)
    }
}

/// `read(int fd, void *buf, size_t count)`
pub struct ReadProcedure {
    table: SimFdTable,
}

impl ReadProcedure {
    pub fn new(table: SimFdTable) -> Self {
        Self { table }
    }
}

impl SimProcedure for ReadProcedure {
    fn name(&self) -> &'static str {
        "read"
    }

    fn apply(&self, state: &SimState) -> SimResult {
        let fd = state.get_arg(0) as i32;
        let buf = state.get_arg(1);
        let count = (state.get_arg(2) as usize).min(65536);

        if !self.table.is_valid(fd) {
            return SimResult::Return(u64::MAX); // -1 EBADF
        }

        // Return simulated synthetic payload or zeros
        let zeros = vec![0u8; count];
        let mut next = state.clone();
        next.write_memory(buf, zeros);
        next.return_value = Some(count as u64);
        next.set_reg(0, count as u64);
        SimResult::Continue(next)
    }
}

/// `write(int fd, const void *buf, size_t count)`
pub struct WriteProcedure {
    table: SimFdTable,
}

impl WriteProcedure {
    pub fn new(table: SimFdTable) -> Self {
        Self { table }
    }
}

impl SimProcedure for WriteProcedure {
    fn name(&self) -> &'static str {
        "write"
    }

    fn apply(&self, state: &SimState) -> SimResult {
        let fd = state.get_arg(0) as i32;
        let buf = state.get_arg(1);
        let count = (state.get_arg(2) as usize).min(65536);

        if !self.table.is_valid(fd) {
            return SimResult::Return(u64::MAX); // -1 EBADF
        }

        let _written = state.read_bytes(buf, count);
        SimResult::Return(count as u64)
    }
}

/// `lseek(int fd, off_t offset, int whence)`
pub struct LseekProcedure {
    table: SimFdTable,
}

impl LseekProcedure {
    pub fn new(table: SimFdTable) -> Self {
        Self { table }
    }
}

impl SimProcedure for LseekProcedure {
    fn name(&self) -> &'static str {
        "lseek"
    }

    fn apply(&self, state: &SimState) -> SimResult {
        let fd = state.get_arg(0) as i32;
        let offset = state.get_arg(1);

        if !self.table.is_valid(fd) {
            return SimResult::Return(u64::MAX);
        }
        SimResult::Return(offset)
    }
}

/// `dup(int oldfd)`
pub struct DupProcedure {
    table: SimFdTable,
}

impl DupProcedure {
    pub fn new(table: SimFdTable) -> Self {
        Self { table }
    }
}

impl SimProcedure for DupProcedure {
    fn name(&self) -> &'static str {
        "dup"
    }

    fn apply(&self, state: &SimState) -> SimResult {
        let oldfd = state.get_arg(0) as i32;
        if !self.table.is_valid(oldfd) {
            return SimResult::Return(u64::MAX);
        }
        let newfd = self.table.alloc_fd(FdKind::File {
            path: "<duplicated>".into(),
            flags: 0,
            offset: 0,
        });
        SimResult::Return(newfd as u32 as u64)
    }
}

/// `pipe(int pipefd[2])`
pub struct PipeProcedure {
    table: SimFdTable,
}

impl PipeProcedure {
    pub fn new(table: SimFdTable) -> Self {
        Self { table }
    }
}

impl SimProcedure for PipeProcedure {
    fn name(&self) -> &'static str {
        "pipe"
    }

    fn apply(&self, state: &SimState) -> SimResult {
        let pipefd_addr = state.get_arg(0);
        let read_fd = self.table.alloc_fd(FdKind::Pipe { read_end: true, peer_fd: -1 });
        let write_fd = self.table.alloc_fd(FdKind::Pipe { read_end: false, peer_fd: read_fd });

        let mut data = Vec::with_capacity(8);
        data.extend_from_slice(&read_fd.to_le_bytes());
        data.extend_from_slice(&write_fd.to_le_bytes());

        let mut next = state.clone();
        next.write_memory(pipefd_addr, data);
        next.return_value = Some(0);
        next.set_reg(0, 0);
        SimResult::Continue(next)
    }
}

/// `socket(int domain, int type, int protocol)`
pub struct SocketProcedure {
    table: SimFdTable,
}

impl SocketProcedure {
    pub fn new(table: SimFdTable) -> Self {
        Self { table }
    }
}

impl SimProcedure for SocketProcedure {
    fn name(&self) -> &'static str {
        "socket"
    }

    fn apply(&self, state: &SimState) -> SimResult {
        let domain = state.get_arg(0) as i32;
        let sock_type = state.get_arg(1) as i32;
        let protocol = state.get_arg(2) as i32;

        let fd = self.table.alloc_fd(FdKind::Socket {
            domain,
            sock_type,
            protocol,
            connected: false,
        });
        SimResult::Return(fd as u32 as u64)
    }
}

/// `connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen)`
pub struct ConnectProcedure {
    table: SimFdTable,
}

impl ConnectProcedure {
    pub fn new(table: SimFdTable) -> Self {
        Self { table }
    }
}

impl SimProcedure for ConnectProcedure {
    fn name(&self) -> &'static str {
        "connect"
    }

    fn apply(&self, state: &SimState) -> SimResult {
        let sockfd = state.get_arg(0) as i32;
        if !self.table.is_valid(sockfd) {
            return SimResult::Return(u64::MAX);
        }
        SimResult::Return(0)
    }
}

/// `bind(int sockfd, const struct sockaddr *addr, socklen_t addrlen)`
pub struct BindProcedure {
    table: SimFdTable,
}

impl BindProcedure {
    pub fn new(table: SimFdTable) -> Self {
        Self { table }
    }
}

impl SimProcedure for BindProcedure {
    fn name(&self) -> &'static str {
        "bind"
    }

    fn apply(&self, state: &SimState) -> SimResult {
        let sockfd = state.get_arg(0) as i32;
        if !self.table.is_valid(sockfd) {
            return SimResult::Return(u64::MAX);
        }
        SimResult::Return(0)
    }
}

/// `listen(int sockfd, int backlog)`
pub struct ListenProcedure {
    table: SimFdTable,
}

impl ListenProcedure {
    pub fn new(table: SimFdTable) -> Self {
        Self { table }
    }
}

impl SimProcedure for ListenProcedure {
    fn name(&self) -> &'static str {
        "listen"
    }

    fn apply(&self, state: &SimState) -> SimResult {
        let sockfd = state.get_arg(0) as i32;
        if !self.table.is_valid(sockfd) {
            return SimResult::Return(u64::MAX);
        }
        SimResult::Return(0)
    }
}

/// `accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen)`
pub struct AcceptProcedure {
    table: SimFdTable,
}

impl AcceptProcedure {
    pub fn new(table: SimFdTable) -> Self {
        Self { table }
    }
}

impl SimProcedure for AcceptProcedure {
    fn name(&self) -> &'static str {
        "accept"
    }

    fn apply(&self, state: &SimState) -> SimResult {
        let sockfd = state.get_arg(0) as i32;
        if !self.table.is_valid(sockfd) {
            return SimResult::Return(u64::MAX);
        }
        let client_fd = self.table.alloc_fd(FdKind::Socket {
            domain: 2, // AF_INET
            sock_type: 1, // SOCK_STREAM
            protocol: 0,
            connected: true,
        });
        SimResult::Return(client_fd as u32 as u64)
    }
}

/// `send(int sockfd, const void *buf, size_t len, int flags)`
pub struct SendProcedure {
    table: SimFdTable,
}

impl SendProcedure {
    pub fn new(table: SimFdTable) -> Self {
        Self { table }
    }
}

impl SimProcedure for SendProcedure {
    fn name(&self) -> &'static str {
        "send"
    }

    fn apply(&self, state: &SimState) -> SimResult {
        let sockfd = state.get_arg(0) as i32;
        let len = state.get_arg(2);
        if !self.table.is_valid(sockfd) {
            return SimResult::Return(u64::MAX);
        }
        SimResult::Return(len)
    }
}

/// `recv(int sockfd, void *buf, size_t len, int flags)`
pub struct RecvProcedure {
    table: SimFdTable,
}

impl RecvProcedure {
    pub fn new(table: SimFdTable) -> Self {
        Self { table }
    }
}

impl SimProcedure for RecvProcedure {
    fn name(&self) -> &'static str {
        "recv"
    }

    fn apply(&self, state: &SimState) -> SimResult {
        let sockfd = state.get_arg(0) as i32;
        let buf = state.get_arg(1);
        let len = (state.get_arg(2) as usize).min(65536);

        if !self.table.is_valid(sockfd) {
            return SimResult::Return(u64::MAX);
        }
        let zeros = vec![0u8; len];
        let mut next = state.clone();
        next.write_memory(buf, zeros);
        next.return_value = Some(len as u64);
        next.set_reg(0, len as u64);
        SimResult::Continue(next)
    }
}

/// `stat(const char *pathname, struct stat *statbuf)`
pub struct StatProcedure;

impl SimProcedure for StatProcedure {
    fn name(&self) -> &'static str {
        "stat"
    }

    fn apply(&self, state: &SimState) -> SimResult {
        let statbuf = state.get_arg(1);
        let mut buf = vec![0u8; 144]; // standard sizeof(struct stat) on x86-64
        // Mode regular file (0100644)
        buf[24..28].copy_from_slice(&(0o100644u32).to_le_bytes());
        // Size 1024
        buf[48..56].copy_from_slice(&1024u64.to_le_bytes());

        let mut next = state.clone();
        next.write_memory(statbuf, buf);
        next.return_value = Some(0);
        next.set_reg(0, 0);
        SimResult::Continue(next)
    }
}

/// `fstat(int fd, struct stat *statbuf)`
pub struct FstatProcedure;

impl SimProcedure for FstatProcedure {
    fn name(&self) -> &'static str {
        "fstat"
    }

    fn apply(&self, state: &SimState) -> SimResult {
        let statbuf = state.get_arg(1);
        let mut buf = vec![0u8; 144];
        buf[24..28].copy_from_slice(&(0o100644u32).to_le_bytes());
        buf[48..56].copy_from_slice(&1024u64.to_le_bytes());

        let mut next = state.clone();
        next.write_memory(statbuf, buf);
        next.return_value = Some(0);
        next.set_reg(0, 0);
        SimResult::Continue(next)
    }
}

/// `access(const char *pathname, int mode)`
pub struct AccessProcedure;

impl SimProcedure for AccessProcedure {
    fn name(&self) -> &'static str {
        "access"
    }

    fn apply(&self, _state: &SimState) -> SimResult {
        SimResult::Return(0)
    }
}

/// `unlink(const char *pathname)`
pub struct UnlinkProcedure;

impl SimProcedure for UnlinkProcedure {
    fn name(&self) -> &'static str {
        "unlink"
    }

    fn apply(&self, _state: &SimState) -> SimResult {
        SimResult::Return(0)
    }
}

/// `mkdir(const char *pathname, mode_t mode)`
pub struct MkdirProcedure;

impl SimProcedure for MkdirProcedure {
    fn name(&self) -> &'static str {
        "mkdir"
    }

    fn apply(&self, _state: &SimState) -> SimResult {
        SimResult::Return(0)
    }
}

/// `rmdir(const char *pathname)`
pub struct RmdirProcedure;

impl SimProcedure for RmdirProcedure {
    fn name(&self) -> &'static str {
        "rmdir"
    }

    fn apply(&self, _state: &SimState) -> SimResult {
        SimResult::Return(0)
    }
}

/// `getcwd(char *buf, size_t size)`
pub struct GetcwdProcedure;

impl SimProcedure for GetcwdProcedure {
    fn name(&self) -> &'static str {
        "getcwd"
    }

    fn apply(&self, state: &SimState) -> SimResult {
        let buf = state.get_arg(0);
        let size = state.get_arg(1) as usize;
        let path = b"/home/user/workspace\0".to_vec();
        if size > 0 && size < path.len() {
            return SimResult::Return(0); // ERANGE
        }

        let mut next = state.clone();
        next.write_memory(buf, path);
        next.return_value = Some(buf);
        next.set_reg(0, buf);
        SimResult::Continue(next)
    }
}

/// `chdir(const char *path)`
pub struct ChdirProcedure;

impl SimProcedure for ChdirProcedure {
    fn name(&self) -> &'static str {
        "chdir"
    }

    fn apply(&self, _state: &SimState) -> SimResult {
        SimResult::Return(0)
    }
}

/// `poll(struct pollfd *fds, nfds_t nfds, int timeout)`
pub struct PollProcedure;

impl SimProcedure for PollProcedure {
    fn name(&self) -> &'static str {
        "poll"
    }

    fn apply(&self, state: &SimState) -> SimResult {
        let nfds = state.get_arg(1);
        SimResult::Return(nfds)
    }
}

/// `select(int nfds, fd_set *readfds, fd_set *writefds, fd_set *exceptfds, struct timeval *timeout)`
pub struct SelectProcedure;

impl SimProcedure for SelectProcedure {
    fn name(&self) -> &'static str {
        "select"
    }

    fn apply(&self, state: &SimState) -> SimResult {
        let nfds = state.get_arg(0);
        SimResult::Return(nfds.min(1))
    }
}
