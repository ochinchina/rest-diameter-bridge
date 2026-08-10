
use rest_diameter_bridge::command::Command;
use rest_diameter_bridge::transport::AnswerManager;
use std::sync::Arc;
use tokio::time::{Duration, timeout};

fn make_command(hop_by_hop_id: u32) -> Command {
    Command::new(272, 0x00, 4, hop_by_hop_id, 1000, vec![])
}

#[tokio::test]
async fn test_prepare_and_wait_answer() {
    let am = AnswerManager::new();
    let hop_id = 1u32;

    am.prepare_for_answer(
        hop_id,
        "conn-1".to_string(),
        "host.example.com".to_string(),
        "example.com".to_string(),
    )
    .await;

    let am_ref = Arc::new(am);
    let am_clone = am_ref.clone();

    let waiter = tokio::spawn(async move { am_clone.wait_answer(hop_id).await });

    // Give the waiter task a moment to start waiting
    tokio::task::yield_now().await;

    let answer = make_command(hop_id);
    let result = am_ref.answer_received(answer.clone()).await;

    assert!(result.is_some());
    let (conn_id, host, realm) = result.unwrap();
    assert_eq!(conn_id, "conn-1");
    assert_eq!(host, "host.example.com");
    assert_eq!(realm, "example.com");

    let waited = waiter.await.unwrap();
    assert!(waited.is_some());
    assert_eq!(waited.unwrap().hop_by_hop_id, hop_id);
}

#[tokio::test]
async fn test_answer_received_without_prepare_returns_none() {
    let am = AnswerManager::new();
    let answer = make_command(999);
    let result = am.answer_received(answer).await;
    assert!(result.is_none());
}

#[tokio::test]
async fn test_wait_answer_without_prepare_returns_none() {
    let am = AnswerManager::new();
    let result = am.wait_answer(42).await;
    assert!(result.is_none());
}

#[tokio::test]
async fn test_multiple_concurrent_answers() {
    let am = Arc::new(AnswerManager::new());

    for i in 1..=5u32 {
        am.prepare_for_answer(
            i,
            format!("conn-{}", i),
            format!("host-{}.example.com", i),
            "example.com".to_string(),
        )
        .await;
    }

    let mut waiters = vec![];
    for i in 1..=5u32 {
        let am_clone = am.clone();
        waiters.push(tokio::spawn(async move { am_clone.wait_answer(i).await }));
    }

    tokio::task::yield_now().await;

    // Send answers in reverse order
    for i in (1..=5u32).rev() {
        let answer = make_command(i);
        let result = am.answer_received(answer).await;
        assert!(result.is_some());
        let (conn_id, _, _) = result.unwrap();
        assert_eq!(conn_id, format!("conn-{}", i));
    }

    for (idx, waiter) in waiters.into_iter().enumerate() {
        let waited = waiter.await.unwrap();
        assert!(waited.is_some());
        assert_eq!(waited.unwrap().hop_by_hop_id, (idx as u32) + 1);
    }
}

#[tokio::test]
async fn test_answer_received_returns_correct_metadata() {
    let am = AnswerManager::new();

    am.prepare_for_answer(
        10,
        "connection-abc".to_string(),
        "diameter.server.net".to_string(),
        "server.net".to_string(),
    )
    .await;

    let answer = make_command(10);
    let result = am.answer_received(answer).await;
    assert!(result.is_some());
    let (conn_id, host, realm) = result.unwrap();
    assert_eq!(conn_id, "connection-abc");
    assert_eq!(host, "diameter.server.net");
    assert_eq!(realm, "server.net");
}

#[tokio::test]
async fn test_prepare_overwrites_existing_entry() {
    let am = AnswerManager::new();

    am.prepare_for_answer(
        7,
        "conn-old".to_string(),
        "old-host".to_string(),
        "old-realm".to_string(),
    )
    .await;

    am.prepare_for_answer(
        7,
        "conn-new".to_string(),
        "new-host".to_string(),
        "new-realm".to_string(),
    )
    .await;

    let answer = make_command(7);
    let result = am.answer_received(answer).await;
    assert!(result.is_some());
    let (conn_id, host, realm) = result.unwrap();
    assert_eq!(conn_id, "conn-new");
    assert_eq!(host, "new-host");
    assert_eq!(realm, "new-realm");
}

#[tokio::test]
async fn test_wait_answer_with_timeout() {
    let am = Arc::new(AnswerManager::new());
    let hop_id = 50u32;

    am.prepare_for_answer(
        hop_id,
        "conn-timeout".to_string(),
        "host".to_string(),
        "realm".to_string(),
    )
    .await;

    let am_clone = am.clone();
    let waiter = tokio::spawn(async move { am_clone.wait_answer(hop_id).await });

    // The waiter should not resolve within 100ms since no answer is sent
    let result = timeout(Duration::from_millis(100), waiter).await;
    assert!(result.is_err(), "Expected timeout since no answer was sent");
}

#[tokio::test]
async fn test_answer_received_twice_same_hop_id() {
    let am = AnswerManager::new();
    let hop_id = 20u32;

    am.prepare_for_answer(
        hop_id,
        "conn-1".to_string(),
        "host".to_string(),
        "realm".to_string(),
    )
    .await;

    let answer1 = make_command(hop_id);
    let result1 = am.answer_received(answer1).await;
    assert!(result1.is_some());

    // Second answer with same hop_by_hop_id still finds the entry (not cleaned up yet)
    let answer2 = make_command(hop_id);
    let result2 = am.answer_received(answer2).await;
    assert!(result2.is_some());
}
