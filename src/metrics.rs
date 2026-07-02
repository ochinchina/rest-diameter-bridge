use lazy_static::lazy_static;
use prometheus::{Encoder, IntCounter, Registry, TextEncoder};

lazy_static! {
    pub static ref REGISTRY: Registry = Registry::new();
    pub static ref REQUESTS_RECEIVED: IntCounter = IntCounter::new(
        "diameter_requests_received_total",
        "Total number of Diameter requests received"
    )
    .unwrap();
    pub static ref RESPONSES_RECEIVED: IntCounter = IntCounter::new(
        "diameter_responses_received_total",
        "Total number of Diameter responses received"
    )
    .unwrap();
    pub static ref RETRIED_REQUESTS: IntCounter = IntCounter::new(
        "diameter_retried_requests_total",
        "Total number of retried Diameter requests"
    )
    .unwrap();
    pub static ref RESTFUL_REQUESTS: IntCounter = IntCounter::new(
        "diameter_restful_requests_total",
        "Total number of requests received from RESTful API"
    )
    .unwrap();
    pub static ref PROCESSED_REQUESTS: IntCounter = IntCounter::new(
        "diameter_processed_requests_total",
        "Total number of requests processed by this node"
    )
    .unwrap();
}

pub fn register_metrics() {
    REGISTRY
        .register(Box::new(REQUESTS_RECEIVED.clone()))
        .unwrap();
    REGISTRY
        .register(Box::new(RESPONSES_RECEIVED.clone()))
        .unwrap();
    REGISTRY
        .register(Box::new(RETRIED_REQUESTS.clone()))
        .unwrap();
    REGISTRY
        .register(Box::new(RESTFUL_REQUESTS.clone()))
        .unwrap();
    REGISTRY
        .register(Box::new(PROCESSED_REQUESTS.clone()))
        .unwrap();
}

pub fn gather_metrics() -> String {
    let encoder = TextEncoder::new();
    let metric_families = REGISTRY.gather();
    let mut buffer = Vec::new();
    encoder.encode(&metric_families, &mut buffer).unwrap();
    String::from_utf8(buffer).unwrap()
}
