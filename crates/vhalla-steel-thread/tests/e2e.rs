#![allow(missing_docs)]

use vhalla_core::EventId;
use vhalla_policy::Operation;
use vhalla_steel_thread::run_once;

#[test]
fn e2e_receipt_is_distinct_from_delivery() {
    let result = run_once().expect("steel thread should complete");
    assert_eq!(result.host.event_id, EventId(30));
    assert_eq!(result.host.operation, Operation::ReadMemory);
    assert!(result.delivered_bytes >= 78);
}
