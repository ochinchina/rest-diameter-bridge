use std::sync::Arc;

use rest_diameter_bridge::command::Command;
use rest_diameter_bridge::transport::{HopByHopIdMapper, IdGenerator};

fn make_id_generator() -> IdGenerator {
    IdGenerator::new()
}
fn make_mapper() -> HopByHopIdMapper {
    HopByHopIdMapper::new()
}

fn make_answer_manager() -> Arc<Box<rest_diameter_bridge::transport::AnswerManager>> {
    Arc::new(Box::new(
        rest_diameter_bridge::transport::AnswerManager::new(),
    ))
}
async fn test_allocate(
    id_generator: &IdGenerator,
    mapper: &HopByHopIdMapper,
    original_id: u32,
) -> u32 {
    let new_hop_by_hop_id = id_generator.next_id();
    mapper.add_mapping(new_hop_by_hop_id, original_id).await;
    new_hop_by_hop_id
}

async fn test_remove(mapper: &HopByHopIdMapper, new_id: u32, result_code: u32) -> Option<u32> {
    let mut cmd = Command::new(272, 0x00, 0, new_id, 0, vec![]);
    cmd.set_result_code(result_code);
    mapper.remove_mapping(new_id).await
}

#[tokio::test]
async fn test_allocate_returns_unique_ids() {
    let mapper = make_mapper();

    let id_generator = make_id_generator();
    let new_id_1 = test_allocate(&id_generator, &mapper, 100).await;
    let new_id_2 = test_allocate(&id_generator, &mapper, 200).await;
    let new_id_3 = test_allocate(&id_generator, &mapper, 300).await;

    assert_ne!(new_id_1, new_id_2);
    assert_ne!(new_id_2, new_id_3);
    assert_ne!(new_id_1, new_id_3);
}

#[tokio::test]
async fn test_allocate_same_original_id_returns_different_new_ids() {
    let mapper = make_mapper();

    let id_generator = make_id_generator();
    let new_id_1 = test_allocate(&id_generator, &mapper, 100).await;
    let new_id_2 = test_allocate(&id_generator, &mapper, 100).await;

    assert_ne!(new_id_1, new_id_2);
}

#[tokio::test]
async fn test_get_returns_original_id() {
    let mapper = make_mapper();

    let id_generator = make_id_generator();
    let new_id = test_allocate(&id_generator, &mapper, 42).await;
    let original = mapper.get_original_id(&new_id).await;

    assert_eq!(original, Some(42));
}

#[tokio::test]
async fn test_get_nonexistent_returns_none() {
    let mapper = make_mapper();

    assert_eq!(mapper.get_original_id(&999).await, None);
}

#[tokio::test]
async fn test_remove_returns_original_id() {
    let mapper = make_mapper();

    let id_generator = make_id_generator();
    let new_id = test_allocate(&id_generator, &mapper, 55).await;
    let original = test_remove(&mapper, new_id, 2001).await;

    assert_eq!(original, Some(55));
}

#[tokio::test]
async fn test_remove_nonexistent_returns_none() {
    let mapper = make_mapper();

    let result = test_remove(&mapper, 12345, 2001).await;
    assert_eq!(result, None);
}

#[tokio::test]
async fn test_remove_clears_mapping() {
    let mapper = make_mapper();

    let id_generator = make_id_generator();
    let new_id = test_allocate(&id_generator, &mapper, 77).await;
    test_remove(&mapper, new_id, 2001).await;

    // After removal, get should return None
    assert_eq!(mapper.get_original_id(&new_id).await, None);
}

#[tokio::test]
async fn test_remove_twice_returns_none_second_time() {
    let mapper = make_mapper();

    let id_generator = make_id_generator();
    let new_id = test_allocate(&id_generator, &mapper, 88).await;
    let first = test_remove(&mapper, new_id, 2001).await;
    let second = test_remove(&mapper, new_id, 2001).await;

    assert_eq!(first, Some(88));
    assert_eq!(second, None);
}

#[tokio::test]
async fn test_multiple_allocations_independent() {
    let mapper = make_mapper();

    let id_generator = make_id_generator();
    let new_a = test_allocate(&id_generator, &mapper, 10).await;
    let new_b = test_allocate(&id_generator, &mapper, 20).await;
    let new_c = test_allocate(&id_generator, &mapper, 30).await;

    assert_eq!(mapper.get_original_id(&new_a).await, Some(10));
    assert_eq!(mapper.get_original_id(&new_b).await, Some(20));
    assert_eq!(mapper.get_original_id(&new_c).await, Some(30));

    // Remove one doesn't affect others
    test_remove(&mapper, new_b, 2001).await;
    assert_eq!(mapper.get_original_id(&new_a).await, Some(10));
    assert_eq!(mapper.get_original_id(&new_b).await, None);
    assert_eq!(mapper.get_original_id(&new_c).await, Some(30));
}

#[tokio::test]
async fn test_wait_for_answer_returns_result_code() {
    let answer_manager = make_answer_manager();
    let mapper = make_mapper();

    let id_generator = make_id_generator();
    let new_id = test_allocate(&id_generator, &mapper, 100).await;

    answer_manager
        .prepare_for_answer(
            new_id,
            "connection-1".to_string(),
            "host".to_string(),
            "realm".to_string(),
        )
        .await;
    let answer_manager_clone = answer_manager.clone();
    let handle = tokio::spawn(async move { answer_manager_clone.wait_answer(new_id).await });

    // Simulate receiving an answer with result code 2001
    tokio::task::yield_now().await;

    let mut answer = Command::new(272, 0x00, 0, new_id, 0, vec![]);
    answer.set_result_code(2001);
    answer_manager.answer_received(answer).await;

    let result_code = handle.await.unwrap();
    debug_assert!(result_code.is_some());
    assert_eq!(result_code.unwrap().get_result_code(), Some(2001));
}

#[tokio::test]
async fn test_wait_for_answer_returns_success_when_no_mapping() {
    let answer_manager = make_answer_manager();

    // No allocation for this ID, should return DiameterUnknownSessionId (5002)
    let result = answer_manager.wait_answer(9999).await;
    assert!(result.is_none());
}

#[tokio::test]
async fn test_wait_for_answer_with_different_result_codes() {
    let mapper = Arc::new(make_mapper());
    let answer_manager = make_answer_manager();

    let id_generator = make_id_generator();
    let new_id = test_allocate(&id_generator, &mapper, 200).await;

    answer_manager
        .prepare_for_answer(
            new_id,
            "connection-2".to_string(),
            "host".to_string(),
            "realm".to_string(),
        )
        .await;
    let answer_manager_clone = answer_manager.clone();
    let handle = tokio::spawn(async move { answer_manager_clone.wait_answer(new_id).await });

    tokio::task::yield_now().await;
    let mut answer = Command::new(272, 0x00, 0, new_id, 0, vec![]);
    answer.set_result_code(3002);
    answer_manager.answer_received(answer).await;

    let result_code = handle.await.unwrap();
    assert!(result_code.is_some());
    assert_eq!(result_code.unwrap().get_result_code(), Some(3002));
}

#[tokio::test]
async fn test_concurrent_allocations_and_removals() {
    let mapper = Arc::new(make_mapper());
    let id_generator: IdGenerator = make_id_generator();

    let mut handles = vec![];
    for i in 0..10 {
        let mapper_clone = mapper.clone();
        let id_generator_clone = id_generator.clone();
        let handle = tokio::spawn(async move {
            let new_id = test_allocate(&id_generator_clone, &mapper_clone, i).await;
            tokio::task::yield_now().await;
            let original = test_remove(&mapper_clone, new_id, 2001).await;
            assert_eq!(original, Some(i));
        });
        handles.push(handle);
    }

    for handle in handles {
        handle.await.unwrap();
    }
}

#[tokio::test]
async fn test_allocate_ids_are_sequential() {
    let mapper = make_mapper();

    let id_generator = make_id_generator();
    let id1 = test_allocate(&id_generator, &mapper, 1).await;
    let id2 = test_allocate(&id_generator, &mapper, 2).await;
    let id3 = test_allocate(&id_generator, &mapper, 3).await;

    assert_eq!(id2, id1 + 1);
    assert_eq!(id3, id2 + 1);
}
