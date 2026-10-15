#![forbid(unsafe_code)]

//! Aggregated POSIX Libc environment simulation procedures.

pub mod heap;
pub mod io;
pub mod process;
pub mod string;

pub use heap::{
    BrkProcedure, CallocProcedure, HeapBlock, HeapViolation, PosixMemalignProcedure, ReallocProcedure,
    TrackedFreeProcedure, TrackedHeap, TrackedMallocProcedure,
};
pub use io::{
    AcceptProcedure, AccessProcedure, BindProcedure, ChdirProcedure, CloseProcedure, ConnectProcedure,
    DupProcedure, FdKind, FstatProcedure, GetcwdProcedure, ListenProcedure, LseekProcedure, MkdirProcedure,
    OpenProcedure, PipeProcedure, PollProcedure, ReadProcedure, RecvProcedure, RmdirProcedure, SelectProcedure,
    SendProcedure, SimFd, SimFdTable, SocketProcedure, StatProcedure, UnlinkProcedure, WriteProcedure,
};
pub use process::{
    AbortProcedure, AbsProcedure, ExecveProcedure, ExitProcedure, ForkProcedure, GetegidProcedure, GeteuidProcedure,
    GetgidProcedure, GetpidProcedure, GetppidProcedure, GettimeofdayProcedure, GetuidProcedure, KillProcedure,
    LabsProcedure, MmapProcedure, MprotectProcedure, MunmapProcedure, NanosleepProcedure, RaiseProcedure,
    RandProcedure, SchedYieldProcedure, SigactionProcedure, SignalProcedure, SleepProcedure, SrandProcedure,
    TimeProcedure, UnameProcedure, WaitpidProcedure,
};
pub use string::{
    AtoiProcedure, AtolProcedure, AtollProcedure, FputsProcedure, IsalnumProcedure, IsalphaProcedure,
    IsdigitProcedure, IsprintProcedure, IsspaceProcedure, IsxdigitProcedure, MemchrProcedure, MemcmpProcedure,
    MemcpyProcedure, MemmoveProcedure, MemrchrProcedure, MemsetProcedure, PutcharProcedure, PutsProcedure,
    SnprintfProcedure, SprintfProcedure, StrcasecmpProcedure, StrcatProcedure, StrchrProcedure, StrcmpProcedure,
    StrcpyProcedure, StrcspnProcedure, StrdupProcedure, StrlenProcedure, StrncasecmpProcedure, StrncatProcedure,
    StrncmpProcedure, StrncpyProcedure, StrndupProcedure, StrrchrProcedure, StrspnProcedure, StrstrProcedure,
    StrtolProcedure, StrtoulProcedure, TolowerProcedure, ToupperProcedure,
};

use crate::SimProcedureRegistry;

/// Registers all POSIX Libc models into the target procedure registry.
pub fn register_posix_procedures(
    registry: &mut SimProcedureRegistry,
    heap: TrackedHeap,
    table: SimFdTable,
) {
    // Heap management
    registry.register(Box::new(TrackedMallocProcedure::new(heap.clone())));
    registry.register(Box::new(CallocProcedure::new(heap.clone())));
    registry.register(Box::new(ReallocProcedure::new(heap.clone())));
    registry.register(Box::new(TrackedFreeProcedure::new(heap.clone())));
    registry.register(Box::new(PosixMemalignProcedure::new(heap.clone())));
    registry.register(Box::new(BrkProcedure::new(heap.clone())));
    registry.register(Box::new(MmapProcedure::new(heap.clone())));
    registry.register(Box::new(MunmapProcedure::new(heap.clone())));

    // Strings & memory
    registry.register(Box::new(StrlenProcedure));
    registry.register(Box::new(StrcmpProcedure));
    registry.register(Box::new(StrncmpProcedure));
    registry.register(Box::new(StrcasecmpProcedure));
    registry.register(Box::new(StrncasecmpProcedure));
    registry.register(Box::new(StrcpyProcedure));
    registry.register(Box::new(StrncpyProcedure));
    registry.register(Box::new(StrcatProcedure));
    registry.register(Box::new(StrncatProcedure));
    registry.register(Box::new(MemcpyProcedure));
    registry.register(Box::new(MemmoveProcedure));
    registry.register(Box::new(MemsetProcedure));
    registry.register(Box::new(MemcmpProcedure));
    registry.register(Box::new(MemchrProcedure));
    registry.register(Box::new(MemrchrProcedure));
    registry.register(Box::new(StrchrProcedure));
    registry.register(Box::new(StrrchrProcedure));
    registry.register(Box::new(StrstrProcedure));
    registry.register(Box::new(StrspnProcedure));
    registry.register(Box::new(StrcspnProcedure));
    registry.register(Box::new(StrdupProcedure::new(heap)));
    registry.register(Box::new(SprintfProcedure));
    registry.register(Box::new(SnprintfProcedure));
    registry.register(Box::new(PutsProcedure));
    registry.register(Box::new(FputsProcedure));
    registry.register(Box::new(PutcharProcedure));

    // Numbers & Character classification
    registry.register(Box::new(AtoiProcedure));
    registry.register(Box::new(AtolProcedure));
    registry.register(Box::new(AtollProcedure));
    registry.register(Box::new(StrtolProcedure));
    registry.register(Box::new(StrtoulProcedure));
    registry.register(Box::new(ToupperProcedure));
    registry.register(Box::new(TolowerProcedure));
    registry.register(Box::new(IsalphaProcedure));
    registry.register(Box::new(IsdigitProcedure));
    registry.register(Box::new(IsalnumProcedure));
    registry.register(Box::new(IsspaceProcedure));
    registry.register(Box::new(IsprintProcedure));
    registry.register(Box::new(IsxdigitProcedure));

    // I/O & Filesystem
    registry.register(Box::new(OpenProcedure::new(table.clone())));
    registry.register(Box::new(CloseProcedure::new(table.clone())));
    registry.register(Box::new(ReadProcedure::new(table.clone())));
    registry.register(Box::new(WriteProcedure::new(table.clone())));
    registry.register(Box::new(LseekProcedure::new(table.clone())));
    registry.register(Box::new(DupProcedure::new(table.clone())));
    registry.register(Box::new(PipeProcedure::new(table.clone())));
    registry.register(Box::new(SocketProcedure::new(table.clone())));
    registry.register(Box::new(ConnectProcedure::new(table.clone())));
    registry.register(Box::new(BindProcedure::new(table.clone())));
    registry.register(Box::new(ListenProcedure::new(table.clone())));
    registry.register(Box::new(AcceptProcedure::new(table.clone())));
    registry.register(Box::new(SendProcedure::new(table.clone())));
    registry.register(Box::new(RecvProcedure::new(table)));
    registry.register(Box::new(StatProcedure));
    registry.register(Box::new(FstatProcedure));
    registry.register(Box::new(AccessProcedure));
    registry.register(Box::new(UnlinkProcedure));
    registry.register(Box::new(MkdirProcedure));
    registry.register(Box::new(RmdirProcedure));
    registry.register(Box::new(GetcwdProcedure));
    registry.register(Box::new(ChdirProcedure));
    registry.register(Box::new(PollProcedure));
    registry.register(Box::new(SelectProcedure));

    // Process & System
    registry.register(Box::new(GetpidProcedure));
    registry.register(Box::new(GetppidProcedure));
    registry.register(Box::new(GetuidProcedure));
    registry.register(Box::new(GeteuidProcedure));
    registry.register(Box::new(GetgidProcedure));
    registry.register(Box::new(GetegidProcedure));
    registry.register(Box::new(ForkProcedure));
    registry.register(Box::new(WaitpidProcedure));
    registry.register(Box::new(ExecveProcedure));
    registry.register(Box::new(ExitProcedure));
    registry.register(Box::new(AbortProcedure));
    registry.register(Box::new(KillProcedure));
    registry.register(Box::new(RaiseProcedure));
    registry.register(Box::new(SigactionProcedure));
    registry.register(Box::new(SignalProcedure));
    registry.register(Box::new(TimeProcedure));
    registry.register(Box::new(GettimeofdayProcedure));
    registry.register(Box::new(NanosleepProcedure));
    registry.register(Box::new(SleepProcedure));
    registry.register(Box::new(UnameProcedure));
    registry.register(Box::new(MprotectProcedure));
    registry.register(Box::new(SchedYieldProcedure));
    registry.register(Box::new(RandProcedure));
    registry.register(Box::new(SrandProcedure));
    registry.register(Box::new(AbsProcedure));
    registry.register(Box::new(LabsProcedure));
}
