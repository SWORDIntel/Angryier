//! Regression suite for the exact Microsoft x64 ABI and tracked event state.

use angryier_models::win32::file::{Win32HandleKind, Win32HandleTable};
use angryier_models::win32::{
    CreateEventAProcedure, CreateEventWProcedure, ResetEventProcedure, SetEventProcedure,
    WaitForMultipleObjectsProcedure, WaitForSingleObjectProcedure,
};
use angryier_models::{SimProcedure, SimResult, SimState};

fn make_event(handles: &Win32HandleTable, manual: bool, initial: bool) -> Result<u64, String> {
    let proc = CreateEventWProcedure::new(handles.clone());
    let mut state = SimState::new();
    state.set_reg(0, 0xdead_beef); // misleading RAX / generic positional arg0
    state.set_reg(1, 0); // security attributes, RCX
    state.set_reg(2, u64::from(manual)); // bManualReset, RDX
    state.set_reg(8, u64::from(initial)); // bInitialState, R8
    state.set_reg(9, 0); // lpName, R9
    match proc.apply(&state) {
        SimResult::Return(handle) if handle != 0 => Ok(handle),
        other => Err(format!("CreateEventW failed: {other:?}")),
    }
}

fn harg(handle: u64, timeout: u32) -> SimState {
    let mut state = SimState::new();
    state.set_reg(1, handle);
    state.set_reg(2, u64::from(timeout));
    state
}

#[test]
fn win64_args_are_not_read_from_rax_and_event_state_is_shared() -> Result<(), String> {
    let handles = Win32HandleTable::new();
    let event = make_event(&handles, false, false)?;
    assert_eq!(
        handles.get_kind(event),
        Some(Win32HandleKind::Event {
            manual_reset: false,
            signaled: false,
        })
    );
    let wait = WaitForSingleObjectProcedure::new(handles.clone());
    assert_eq!(wait.apply(&harg(event, 0)), SimResult::Return(258)); // zero-time poll
    assert_eq!(
        wait.apply(&harg(event, u32::MAX)),
        SimResult::Blocked {
            handle: event,
            timeout_ms: u32::MAX,
        }
    );
    let set = SetEventProcedure::new(handles.clone());
    let reset = ResetEventProcedure::new(handles.clone());
    assert_eq!(set.apply(&harg(event, 0)), SimResult::Return(1));
    assert_eq!(wait.apply(&harg(event, 0)), SimResult::Return(0));
    assert_eq!(wait.apply(&harg(event, 0)), SimResult::Return(258)); // auto-reset
    assert_eq!(set.apply(&harg(event, 0)), SimResult::Return(1));
    assert_eq!(reset.apply(&harg(event, 0)), SimResult::Return(1));
    assert_eq!(wait.apply(&harg(event, 0)), SimResult::Return(258));
    assert_eq!(set.apply(&harg(0xbad, 0)), SimResult::Return(0));
    assert_eq!(wait.apply(&harg(0xbad, 0)), SimResult::Return(0xffff_ffff));
    Ok(())
}

#[test]
fn manual_reset_wakes_repeated_pollers_until_reset() -> Result<(), String> {
    let handles = Win32HandleTable::new();
    let event = make_event(&handles, true, true)?;
    let wait = WaitForSingleObjectProcedure::new(handles.clone());
    assert_eq!(wait.apply(&harg(event, 0)), SimResult::Return(0));
    assert_eq!(wait.apply(&harg(event, 0)), SimResult::Return(0));
    let reset = ResetEventProcedure::new(handles);
    assert_eq!(reset.apply(&harg(event, 0)), SimResult::Return(1));
    assert_eq!(wait.apply(&harg(event, 0)), SimResult::Return(258));
    Ok(())
}

#[test]
fn wait_all_is_atomic_and_wait_any_consumes_lowest_auto_reset() -> Result<(), String> {
    let handles = Win32HandleTable::new();
    let one = make_event(&handles, false, true)?;
    let two = make_event(&handles, false, false)?;
    let proc = WaitForMultipleObjectsProcedure::new(handles.clone());
    let mut state = SimState::new();
    state.set_reg(1, 2); // nCount
    state.set_reg(2, 0x1234); // lpHandles
    state.set_reg(8, 1); // bWaitAll
    state.set_reg(9, 0); // timeout = 0
    let mut list = Vec::new();
    list.extend_from_slice(&one.to_le_bytes());
    list.extend_from_slice(&two.to_le_bytes());
    state.shadow_memory(0x1234, list);
    assert_eq!(proc.apply(&state), SimResult::Return(258));
    // Wait-all failed: first event must remain signaled.
    assert_eq!(
        handles.get_kind(one),
        Some(Win32HandleKind::Event {
            signaled: true,
            manual_reset: false,
        })
    );
    let set = SetEventProcedure::new(handles.clone());
    assert_eq!(set.apply(&harg(two, 0)), SimResult::Return(1));
    assert_eq!(proc.apply(&state), SimResult::Return(0));
    assert_eq!(
        handles.get_kind(one),
        Some(Win32HandleKind::Event {
            signaled: false,
            manual_reset: false,
        })
    );

    // Either event can now be signaled; wait-any returns its zero-based index.
    assert_eq!(set.apply(&harg(two, 0)), SimResult::Return(1));
    state.set_reg(8, 0);
    assert_eq!(proc.apply(&state), SimResult::Return(1));
    assert_eq!(proc.apply(&state), SimResult::Return(258));
    Ok(())
}

#[test]
fn absent_handle_memory_and_missing_arguments_cannot_create_success() {
    let handles = Win32HandleTable::new();
    let event = CreateEventAProcedure::new(handles.clone());
    assert!(matches!(event.apply(&SimState::new()), SimResult::Unsupported(_)));
    let wait = WaitForMultipleObjectsProcedure::new(handles);
    let mut state = SimState::new();
    state.set_reg(1, 1);
    state.set_reg(2, 0x1234);
    state.set_reg(8, 0);
    state.set_reg(9, u64::from(u32::MAX));
    assert!(matches!(wait.apply(&state), SimResult::Unsupported(_)));
}
