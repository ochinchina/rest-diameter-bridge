use std::sync::Arc;

use rest_diameter_bridge::transport::{HopByHopIdMapper, IdGenerator};

fn make_mapper() -> HopByHopIdMapper {
    let generator = Arc::new(IdGenerator::new());
    HopByHopIdMapper::new(generator)
}

#[test]
fn test_allocate_returns_unique_ids() {
    let mapper = make_mapper();

    let new_id_1 = mapper.allocate(100);
    let new_id_2 = mapper.allocate(200);
    let new_id_3 = mapper.allocate(300);

    assert_ne!(new_id_1, new_id_2);
    assert_ne!(new_id_2, new_id_3);
    assert_ne!(new_id_1, new_id_3);
}

#[test]
fn test_allocate_same_original_id_returns_different_new_ids() {
    let mapper = make_mapper();

    let new_id_1 = mapper.allocate(100);
    let new_id_2 = mapper.allocate(100);

    assert_ne!(new_id_1, new_id_2);
}

#[test]
fn test_get_returns_original_id() {
    let mapper = make_mapper();

    let new_id = mapper.allocate(42);
    let original = mapper.get(&new_id);

    assert_eq!(original, Some(42));
}

#[test]
fn test_get_nonexistent_returns_none() {
    let mapper = make_mapper();

    assert_eq!(mapper.get(&999), None);
}

#[test]
fn test_remove_returns_original_id() {
    let mapper = make_mapper();

    let new_id = mapper.allocate(55);
    let original = mapper.remove(&new_id, 2001);

    assert_eq!(original, Some(55));
}

#[test]
fn test_remove_nonexistent_returns_none() {
    let mapper = make_mapper();

    let result = mapper.remove(&12345, 2001);
    assert_eq!(result, None);
}

#[test]
fn test_remove_clears_mapping() {
    let mapper = make_mapper();

    let new_id = mapper.allocate(77);
    mapper.remove(&new_id, 2001);

    // After removal, get should return None
    assert_eq!(mapper.get(&new_id), None);
}

#[test]
fn test_remove_twice_returns_none_second_time() {
    let mapper = make_mapper();

    let new_id = mapper.allocate(88);
    let first = mapper.remove(&new_id, 2001);
    let second = mapper.remove(&new_id, 2001);

    assert_eq!(first, Some(88));
    assert_eq!(second, None);
}

#[test]
fn test_multiple_allocations_independent() {
    let mapper = make_mapper();

    let new_a = mapper.allocate(10);
    let new_b = mapper.allocate(20);
    let new_c = mapper.allocate(30);

    assert_eq!(mapper.get(&new_a), Some(10));
    assert_eq!(mapper.get(&new_b), Some(20));
    assert_eq!(mapper.get(&new_c), Some(30));

    // Remove one doesn't affect others
    mapper.remove(&new_b, 2001);
    assert_eq!(mapper.get(&new_a), Some(10));
    assert_eq!(mapper.get(&new_b), None);
    assert_eq!(mapper.get(&new_c), Some(30));
}

#[tokio::test]
async fn test_wait_for_answer_returns_result_code() {
    let mapper = Arc::new(make_mapper());

    let new_id = mapper.allocate(100);

    let mapper_clone = mapper.clone();
    let handle = tokio::spawn(async move { mapper_clone.wait_for_answer(new_id).await });

    // Simulate receiving an answer with result code 2001
    tokio::task::yield_now().await;
    mapper.remove(&new_id, 2001);

    let result_code = handle.await.unwrap();
    assert_eq!(result_code, 2001);
}

#[tokio::test]
async fn test_wait_for_answer_returns_success_when_no_mapping() {
    let mapper = make_mapper();

    // No allocation for this ID, should return DiameterSuccess (2001)
    let result = mapper.wait_for_answer(9999).await;
    assert_eq!(result, 2001); // DiameterSuccess
}

#[tokio::test]
async fn test_wait_for_answer_with_different_result_codes() {
    let mapper = Arc::new(make_mapper());

    let new_id = mapper.allocate(200);

    let mapper_clone = mapper.clone();
    let handle = tokio::spawn(async move { mapper_clone.wait_for_answer(new_id).await });

    tokio::task::yield_now().await;
    mapper.remove(&new_id, 3002); // DIAMETER_UNABLE_TO_DELIVER

    let result_code = handle.await.unwrap();
    assert_eq!(result_code, 3002);
}

#[tokio::test]
async fn test_concurrent_allocations_and_removals() {
    let mapper = Arc::new(make_mapper());

    let mut handles = vec![];
    for i in 0..10 {
        let mapper_clone = mapper.clone();
        let handle = tokio::spawn(async move {
            let new_id = mapper_clone.allocate(i);
            tokio::task::yield_now().await;
            let original = mapper_clone.remove(&new_id, 2001);
            assert_eq!(original, Some(i));
        });
        handles.push(handle);
    }

    for handle in handles {
        handle.await.unwrap();
    }
}

#[test]
fn test_allocate_ids_are_sequential() {
    let mapper = make_mapper();

    let id1 = mapper.allocate(1);
    let id2 = mapper.allocate(2);
    let id3 = mapper.allocate(3);

    assert_eq!(id2, id1 + 1);
    assert_eq!(id3, id2 + 1);
}
