use std::sync::Arc;
use std::sync::atomic::AtomicUsize;

use rest_diameter_bridge::transport::{
    Connection, ConnectionIterator, ConnectionList, DummyConnection, FailOverConnection,
    RoundRobinConnection,
};

fn make_conn(id: &str) -> Arc<Box<dyn Connection + Send + Sync>> {
    Arc::new(Box::new(DummyConnection::new(
        id.to_string(),
        format!("{}-host", id),
        format!("{}-realm", id),
    )) as Box<dyn Connection + Send + Sync>)
}

// === Round-Robin Iterator Tests ===

#[tokio::test]
async fn test_roundrobin_iterator_cycles_through_connections() {
    let list = Arc::new(ConnectionList::new(vec![
        make_conn("rr1"),
        make_conn("rr2"),
        make_conn("rr3"),
    ]));

    let iter = ConnectionIterator::new(list, AtomicUsize::new(0));
    let ids: Vec<String> = iter.map(|c| c.get_id()).collect();
    assert_eq!(ids, vec!["rr1", "rr2", "rr3"]);
}

#[tokio::test]
async fn test_roundrobin_iterator_starts_at_offset() {
    let list = Arc::new(ConnectionList::new(vec![
        make_conn("rr1"),
        make_conn("rr2"),
        make_conn("rr3"),
    ]));

    // Start at index 1: should yield rr2, rr3, rr1
    let iter = ConnectionIterator::new(list, AtomicUsize::new(1));
    let ids: Vec<String> = iter.map(|c| c.get_id()).collect();
    assert_eq!(ids, vec!["rr2", "rr3", "rr1"]);
}

#[tokio::test]
async fn test_roundrobin_iterator_starts_at_last_index() {
    let list = Arc::new(ConnectionList::new(vec![
        make_conn("rr1"),
        make_conn("rr2"),
        make_conn("rr3"),
    ]));

    // Start at index 2: should yield rr3, rr1, rr2
    let iter = ConnectionIterator::new(list, AtomicUsize::new(2));
    let ids: Vec<String> = iter.map(|c| c.get_id()).collect();
    assert_eq!(ids, vec!["rr3", "rr1", "rr2"]);
}

#[tokio::test]
async fn test_roundrobin_iterator_single_connection() {
    let list = Arc::new(ConnectionList::new(vec![make_conn("only")]));

    let iter = ConnectionIterator::new(list, AtomicUsize::new(0));
    let ids: Vec<String> = iter.map(|c| c.get_id()).collect();
    assert_eq!(ids, vec!["only"]);
}

#[tokio::test]
async fn test_roundrobin_iterator_empty_list() {
    let list = Arc::new(ConnectionList::new(vec![]));

    let iter = ConnectionIterator::new(list, AtomicUsize::new(0));
    let ids: Vec<String> = iter.map(|c| c.get_id()).collect();
    assert!(ids.is_empty());
}

#[tokio::test]
async fn test_roundrobin_connection_iter_advances_index() {
    let rr = RoundRobinConnection::new(vec![make_conn("rr1"), make_conn("rr2"), make_conn("rr3")]);

    // First iter call
    let ids1: Vec<String> = rr.iter().unwrap().map(|c| c.get_id()).collect();

    // Second iter call should start from a different offset
    let ids2: Vec<String> = rr.iter().unwrap().map(|c| c.get_id()).collect();

    // The two iterations should start from different positions
    assert_ne!(ids1[0], ids2[0]);
    // Both should contain the same 3 connections
    assert_eq!(ids1.len(), 3);
    assert_eq!(ids2.len(), 3);
}

#[tokio::test]
async fn test_roundrobin_iterator_does_not_exceed_connection_count() {
    let list = Arc::new(ConnectionList::new(vec![make_conn("c1"), make_conn("c2")]));

    let iter = ConnectionIterator::new(list, AtomicUsize::new(0));
    let ids: Vec<String> = iter.map(|c| c.get_id()).collect();
    assert_eq!(ids.len(), 2);
}

#[tokio::test]
async fn test_multiple_sequential_iterations_are_independent() {
    let list = Arc::new(ConnectionList::new(vec![make_conn("s1"), make_conn("s2")]));

    let ids1: Vec<String> = ConnectionIterator::new(list.clone(), AtomicUsize::new(0))
        .map(|c| c.get_id())
        .collect();
    let ids2: Vec<String> = ConnectionIterator::new(list, AtomicUsize::new(0))
        .map(|c| c.get_id())
        .collect();

    assert_eq!(ids1, ids2);
}

// === Failover Iterator Tests ===

#[tokio::test]
async fn test_failover_iterator_always_starts_at_zero() {
    let failover =
        FailOverConnection::new(vec![make_conn("fo1"), make_conn("fo2"), make_conn("fo3")]);

    let ids: Vec<String> = failover.iter().unwrap().map(|c| c.get_id()).collect();
    assert_eq!(ids, vec!["fo1", "fo2", "fo3"]);

    // Second call should also start at 0
    let ids2: Vec<String> = failover.iter().unwrap().map(|c| c.get_id()).collect();
    assert_eq!(ids2, vec!["fo1", "fo2", "fo3"]);
}

#[tokio::test]
async fn test_failover_iterator_single_connection() {
    let failover = FailOverConnection::new(vec![make_conn("primary")]);

    let ids: Vec<String> = failover.iter().unwrap().map(|c| c.get_id()).collect();
    assert_eq!(ids, vec!["primary"]);
}

#[tokio::test]
async fn test_failover_iterator_yields_all_in_order() {
    let list = Arc::new(ConnectionList::new(vec![
        make_conn("primary"),
        make_conn("secondary"),
        make_conn("tertiary"),
    ]));

    let iter = ConnectionIterator::new(list, AtomicUsize::new(0));
    let ids: Vec<String> = iter.map(|c| c.get_id()).collect();
    assert_eq!(ids, vec!["primary", "secondary", "tertiary"]);
}

#[tokio::test]
async fn test_failover_iterator_count_matches_connection_count() {
    let conns: Vec<Arc<Box<dyn Connection + Send + Sync>>> =
        (0..5).map(|i| make_conn(&format!("fo{}", i))).collect();

    let list = Arc::new(ConnectionList::new(conns));
    let count = ConnectionIterator::new(list, AtomicUsize::new(0)).count();
    assert_eq!(count, 5);
}

// === Hybrid Round-Robin / Failover Tests ===

#[tokio::test]
async fn test_hybrid_roundrobin_containing_failover_groups() {
    // RoundRobin [ FailOver[a1, a2], FailOver[b1, b2] ]
    let failover_a = Arc::new(Box::new(FailOverConnection::new(vec![
        make_conn("a1"),
        make_conn("a2"),
    ])) as Box<dyn Connection + Send + Sync>);
    let failover_b = Arc::new(Box::new(FailOverConnection::new(vec![
        make_conn("b1"),
        make_conn("b2"),
    ])) as Box<dyn Connection + Send + Sync>);

    let rr = RoundRobinConnection::new(vec![failover_a, failover_b]);

    let ids: Vec<String> = rr.iter().unwrap().map(|c| c.get_id()).collect();

    // Should drain failover_a (a1, a2) then failover_b (b1, b2)
    assert_eq!(ids, vec!["a1", "a2", "b1", "b2"]);
}

#[tokio::test]
async fn test_hybrid_roundrobin_containing_failover_groups_offset() {
    // RoundRobin [ FailOver[a1, a2], FailOver[b1, b2] ]
    let failover_a = Arc::new(Box::new(FailOverConnection::new(vec![
        make_conn("a1"),
        make_conn("a2"),
    ])) as Box<dyn Connection + Send + Sync>);
    let failover_b = Arc::new(Box::new(FailOverConnection::new(vec![
        make_conn("b1"),
        make_conn("b2"),
    ])) as Box<dyn Connection + Send + Sync>);

    let rr = RoundRobinConnection::new(vec![failover_a, failover_b]);

    // Advance the index by consuming the first iterator
    let _ = rr.iter().unwrap().count();

    // Second call starts at failover_b
    let ids: Vec<String> = rr.iter().unwrap().map(|c| c.get_id()).collect();
    assert_eq!(ids, vec!["b1", "b2", "a1", "a2"]);
}

#[tokio::test]
async fn test_hybrid_failover_containing_roundrobin_groups() {
    // FailOver [ RoundRobin[a1, a2], RoundRobin[b1, b2] ]
    let rr_a = Arc::new(Box::new(RoundRobinConnection::new(vec![
        make_conn("a1"),
        make_conn("a2"),
    ])) as Box<dyn Connection + Send + Sync>);
    let rr_b = Arc::new(Box::new(RoundRobinConnection::new(vec![
        make_conn("b1"),
        make_conn("b2"),
    ])) as Box<dyn Connection + Send + Sync>);

    let failover = FailOverConnection::new(vec![rr_a, rr_b]);

    let ids: Vec<String> = failover.iter().unwrap().map(|c| c.get_id()).collect();

    // Should drain rr_a then rr_b; all four leaf connections present
    assert_eq!(ids.len(), 4);
    assert!(ids.contains(&"a1".to_string()));
    assert!(ids.contains(&"a2".to_string()));
    assert!(ids.contains(&"b1".to_string()));
    assert!(ids.contains(&"b2".to_string()));
}

#[tokio::test]
async fn test_hybrid_roundrobin_mixed_plain_and_failover() {
    // RoundRobin [ plain, FailOver[fo1, fo2] ]
    let failover = Arc::new(Box::new(FailOverConnection::new(vec![
        make_conn("fo1"),
        make_conn("fo2"),
    ])) as Box<dyn Connection + Send + Sync>);

    let rr = RoundRobinConnection::new(vec![make_conn("plain"), failover]);

    let ids: Vec<String> = rr.iter().unwrap().map(|c| c.get_id()).collect();

    assert_eq!(ids.len(), 3);
    assert_eq!(ids[0], "plain");
    assert!(ids.contains(&"fo1".to_string()));
    assert!(ids.contains(&"fo2".to_string()));
}

#[tokio::test]
async fn test_hybrid_failover_mixed_plain_and_roundrobin() {
    // FailOver [ plain, RoundRobin[rr1, rr2] ]
    let roundrobin = Arc::new(Box::new(RoundRobinConnection::new(vec![
        make_conn("rr1"),
        make_conn("rr2"),
    ])) as Box<dyn Connection + Send + Sync>);

    let failover = FailOverConnection::new(vec![make_conn("plain"), roundrobin]);

    let ids: Vec<String> = failover.iter().unwrap().map(|c| c.get_id()).collect();

    assert_eq!(ids.len(), 3);
    assert_eq!(ids[0], "plain");
    assert!(ids.contains(&"rr1".to_string()));
    assert!(ids.contains(&"rr2".to_string()));
}

#[tokio::test]
async fn test_hybrid_deeply_nested() {
    // RoundRobin [ FailOver [ RoundRobin[a, b], c ] ]
    let inner_rr = Arc::new(Box::new(RoundRobinConnection::new(vec![
        make_conn("a"),
        make_conn("b"),
    ])) as Box<dyn Connection + Send + Sync>);
    let failover = Arc::new(
        Box::new(FailOverConnection::new(vec![inner_rr, make_conn("c")]))
            as Box<dyn Connection + Send + Sync>,
    );

    let outer_rr = RoundRobinConnection::new(vec![failover]);

    let ids: Vec<String> = outer_rr.iter().unwrap().map(|c| c.get_id()).collect();

    // outer_rr -> failover (container) -> sub_iter: inner_rr -> a, b; then c
    assert_eq!(ids.len(), 3);
    assert!(ids.contains(&"a".to_string()));
    assert!(ids.contains(&"b".to_string()));
    assert!(ids.contains(&"c".to_string()));
}

#[tokio::test]
async fn test_hybrid_failover_first_then_plain() {
    // RoundRobin [ FailOver[fo1, fo2], plain ]
    let failover = Arc::new(Box::new(FailOverConnection::new(vec![
        make_conn("fo1"),
        make_conn("fo2"),
    ])) as Box<dyn Connection + Send + Sync>);

    let rr = RoundRobinConnection::new(vec![failover, make_conn("plain")]);

    let ids: Vec<String> = rr.iter().unwrap().map(|c| c.get_id()).collect();

    assert_eq!(ids.len(), 3);
    // Failover container is first, drains fo1, fo2; then plain
    assert!(ids.contains(&"fo1".to_string()));
    assert!(ids.contains(&"fo2".to_string()));
    assert!(ids.contains(&"plain".to_string()));
}

#[tokio::test]
async fn test_hybrid_roundrobin_with_empty_failover() {
    // RoundRobin [ FailOver[], plain, FailOver[fo1, fo2] ]
    let empty_failover =
        Arc::new(Box::new(FailOverConnection::new(vec![])) as Box<dyn Connection + Send + Sync>);
    let failover = Arc::new(Box::new(FailOverConnection::new(vec![
        make_conn("fo1"),
        make_conn("fo2"),
    ])) as Box<dyn Connection + Send + Sync>);

    let rr = RoundRobinConnection::new(vec![empty_failover, make_conn("plain"), failover]);

    let ids: Vec<String> = rr.iter().unwrap().map(|c| c.get_id()).collect();

    // Empty failover is skipped, yields plain, fo1, fo2
    assert_eq!(ids.len(), 3);
    assert!(ids.contains(&"plain".to_string()));
    assert!(ids.contains(&"fo1".to_string()));
    assert!(ids.contains(&"fo2".to_string()));
}

#[tokio::test]
async fn test_hybrid_failover_with_empty_roundrobin() {
    // FailOver [ RoundRobin[], plain, RoundRobin[rr1, rr2] ]
    let empty_rr =
        Arc::new(Box::new(RoundRobinConnection::new(vec![])) as Box<dyn Connection + Send + Sync>);
    let rr = Arc::new(Box::new(RoundRobinConnection::new(vec![
        make_conn("rr1"),
        make_conn("rr2"),
    ])) as Box<dyn Connection + Send + Sync>);

    let failover = FailOverConnection::new(vec![empty_rr, make_conn("plain"), rr]);

    let ids: Vec<String> = failover.iter().unwrap().map(|c| c.get_id()).collect();

    // Empty roundrobin is skipped, yields plain, rr1, rr2
    assert_eq!(ids.len(), 3);
    assert_eq!(ids[0], "plain");
    assert!(ids.contains(&"rr1".to_string()));
    assert!(ids.contains(&"rr2".to_string()));
}

#[tokio::test]
async fn test_hybrid_roundrobin_all_empty_containers() {
    // RoundRobin [ FailOver[], RoundRobin[] ]
    let empty_failover =
        Arc::new(Box::new(FailOverConnection::new(vec![])) as Box<dyn Connection + Send + Sync>);
    let empty_rr =
        Arc::new(Box::new(RoundRobinConnection::new(vec![])) as Box<dyn Connection + Send + Sync>);

    let rr = RoundRobinConnection::new(vec![empty_failover, empty_rr]);

    let ids: Vec<String> = rr.iter().unwrap().map(|c| c.get_id()).collect();

    assert!(ids.is_empty());
}

#[tokio::test]
async fn test_hybrid_failover_all_empty_containers() {
    // FailOver [ RoundRobin[], FailOver[] ]
    let empty_rr =
        Arc::new(Box::new(RoundRobinConnection::new(vec![])) as Box<dyn Connection + Send + Sync>);
    let empty_failover =
        Arc::new(Box::new(FailOverConnection::new(vec![])) as Box<dyn Connection + Send + Sync>);

    let failover = FailOverConnection::new(vec![empty_rr, empty_failover]);

    assert!(failover.iter().is_some()); // Should return Some iterator, even if empty
    assert!(failover.iter().unwrap().next().is_none()); // Iterator should yield no connections
}

#[tokio::test]
async fn test_hybrid_mixed_empty_and_populated_nested() {
    // RoundRobin [ FailOver[], FailOver[fo1], RoundRobin[], plain, FailOver[fo2, fo3] ]
    let empty_fo =
        Arc::new(Box::new(FailOverConnection::new(vec![])) as Box<dyn Connection + Send + Sync>);
    let fo_single = Arc::new(Box::new(FailOverConnection::new(vec![make_conn("fo1")]))
        as Box<dyn Connection + Send + Sync>);
    let empty_rr =
        Arc::new(Box::new(RoundRobinConnection::new(vec![])) as Box<dyn Connection + Send + Sync>);
    let fo_double = Arc::new(Box::new(FailOverConnection::new(vec![
        make_conn("fo2"),
        make_conn("fo3"),
    ])) as Box<dyn Connection + Send + Sync>);

    let rr = RoundRobinConnection::new(vec![
        empty_fo,
        fo_single,
        empty_rr,
        make_conn("plain"),
        fo_double,
    ]);

    let ids: Vec<String> = rr.iter().unwrap().map(|c| c.get_id()).collect();

    // Empty containers skipped; yields fo1, plain, fo2, fo3
    assert_eq!(ids.len(), 4);
    assert!(ids.contains(&"fo1".to_string()));
    assert!(ids.contains(&"plain".to_string()));
    assert!(ids.contains(&"fo2".to_string()));
    assert!(ids.contains(&"fo3".to_string()));
}
