use rest_diameter_bridge::stack::{ListenAddress, LoadBalancerStrategy};

#[test]
fn test_listen_address_from_str_basic() {
    let addr = ListenAddress::from_str("tcp://127.0.0.1:3868").unwrap();
    assert_eq!(addr.protocol, "tcp");
    assert_eq!(addr.port, 3868);
    assert_eq!(addr.hosts, vec!["127.0.0.1".to_string()]);
    assert!(addr.parameters.is_none());
}

#[test]
fn test_listen_address_from_str_multiple_hosts() {
    let addr = ListenAddress::from_str("tcp://192.168.1.1,192.168.1.2:3868").unwrap();
    assert_eq!(addr.protocol, "tcp");
    assert_eq!(addr.port, 3868);
    assert_eq!(
        addr.hosts,
        vec!["192.168.1.1".to_string(), "192.168.1.2".to_string()]
    );
    assert!(addr.parameters.is_none());
}

#[test]
fn test_listen_address_from_str_with_parameters() {
    let addr = ListenAddress::from_str("tcp://127.0.0.1:3868?tls=true&timeout=5000").unwrap();
    assert_eq!(addr.protocol, "tcp");
    assert_eq!(addr.port, 3868);
    assert_eq!(addr.hosts, vec!["127.0.0.1".to_string()]);
    let params = addr.parameters.unwrap();
    assert_eq!(params.get("tls"), Some(&"true".to_string()));
    assert_eq!(params.get("timeout"), Some(&"5000".to_string()));
}

#[test]
fn test_listen_address_from_str_sctp_protocol() {
    let addr = ListenAddress::from_str("sctp://10.0.0.1:5868").unwrap();
    assert_eq!(addr.protocol, "sctp");
    assert_eq!(addr.port, 5868);
    assert_eq!(addr.hosts, vec!["10.0.0.1".to_string()]);
}

#[test]
fn test_listen_address_from_str_tcp_ipv6_loopback() {
    let addr = ListenAddress::from_str("tcp://[::1]:3868").unwrap();
    assert_eq!(addr.protocol, "tcp");
    assert_eq!(addr.port, 3868);
    assert_eq!(addr.hosts, vec!["[::1]".to_string()]);
    assert!(addr.parameters.is_none());
}

#[test]
fn test_listen_address_from_str_tcp_ipv6_full() {
    let addr = ListenAddress::from_str("tcp://[2001:db8::1]:3868").unwrap();
    assert_eq!(addr.protocol, "tcp");
    assert_eq!(addr.port, 3868);
    assert_eq!(addr.hosts, vec!["[2001:db8::1]".to_string()]);
    assert!(addr.parameters.is_none());
}

// LoadBalancerStrategy::from_str() tests

#[test]
fn test_load_balancer_strategy_round_robin() {
    let result = LoadBalancerStrategy::from_str("round-robin(peer1)");
    assert!(result.is_some());
    match result.unwrap() {
        LoadBalancerStrategy::RoundRobin(peer) => assert_eq!(peer, "peer1"),
        _ => panic!("Expected RoundRobin variant"),
    }
}

#[test]
fn test_load_balancer_strategy_round_robin_short() {
    let result = LoadBalancerStrategy::from_str("rr(peer2)");
    assert!(result.is_some());
    match result.unwrap() {
        LoadBalancerStrategy::RoundRobin(peer) => assert_eq!(peer, "peer2"),
        _ => panic!("Expected RoundRobin variant"),
    }
}

#[test]
fn test_load_balancer_strategy_roundrobin_no_hyphen() {
    let result = LoadBalancerStrategy::from_str("roundrobin(peer3)");
    assert!(result.is_some());
    match result.unwrap() {
        LoadBalancerStrategy::RoundRobin(peer) => assert_eq!(peer, "peer3"),
        _ => panic!("Expected RoundRobin variant"),
    }
}

#[test]
fn test_load_balancer_strategy_failover() {
    let result = LoadBalancerStrategy::from_str("failover(backup-peer)");
    assert!(result.is_some());
    match result.unwrap() {
        LoadBalancerStrategy::FailOver(peer) => assert_eq!(peer, "backup-peer"),
        _ => panic!("Expected FailOver variant"),
    }
}

#[test]
fn test_load_balancer_strategy_failover_short() {
    let result = LoadBalancerStrategy::from_str("fo(backup)");
    assert!(result.is_some());
    match result.unwrap() {
        LoadBalancerStrategy::FailOver(peer) => assert_eq!(peer, "backup"),
        _ => panic!("Expected FailOver variant"),
    }
}

#[test]
fn test_load_balancer_strategy_fail_over_hyphen() {
    let result = LoadBalancerStrategy::from_str("fail-over(peer-x)");
    assert!(result.is_some());
    match result.unwrap() {
        LoadBalancerStrategy::FailOver(peer) => assert_eq!(peer, "peer-x"),
        _ => panic!("Expected FailOver variant"),
    }
}

#[test]
fn test_load_balancer_strategy_random() {
    let result = LoadBalancerStrategy::from_str("random(pool1)");
    assert!(result.is_some());
    match result.unwrap() {
        LoadBalancerStrategy::Random(peer) => assert_eq!(peer, "pool1"),
        _ => panic!("Expected Random variant"),
    }
}

#[test]
fn test_load_balancer_strategy_random_short() {
    let result = LoadBalancerStrategy::from_str("rand(pool2)");
    assert!(result.is_some());
    match result.unwrap() {
        LoadBalancerStrategy::Random(peer) => assert_eq!(peer, "pool2"),
        _ => panic!("Expected Random variant"),
    }
}

#[test]
fn test_load_balancer_strategy_value_single() {
    let result = LoadBalancerStrategy::from_str("peer1");
    assert!(result.is_some());
    match result.unwrap() {
        LoadBalancerStrategy::Value(values) => assert_eq!(values, vec!["peer1".to_string()]),
        _ => panic!("Expected Value variant"),
    }
}

#[test]
fn test_load_balancer_strategy_value_multiple() {
    let result = LoadBalancerStrategy::from_str("peer1;peer2;peer3");
    assert!(result.is_some());
    match result.unwrap() {
        LoadBalancerStrategy::Value(values) => {
            assert_eq!(
                values,
                vec![
                    "peer1".to_string(),
                    "peer2".to_string(),
                    "peer3".to_string()
                ]
            );
        }
        _ => panic!("Expected Value variant"),
    }
}

#[test]
fn test_load_balancer_strategy_value_with_spaces() {
    let result = LoadBalancerStrategy::from_str("peer1 ; peer2 ; peer3");
    assert!(result.is_some());
    match result.unwrap() {
        LoadBalancerStrategy::Value(values) => {
            assert_eq!(
                values,
                vec![
                    "peer1".to_string(),
                    "peer2".to_string(),
                    "peer3".to_string()
                ]
            );
        }
        _ => panic!("Expected Value variant"),
    }
}

#[test]
fn test_load_balancer_strategy_case_insensitive() {
    let result = LoadBalancerStrategy::from_str("Round-Robin(peer1)");
    assert!(result.is_some());
    match result.unwrap() {
        LoadBalancerStrategy::RoundRobin(peer) => assert_eq!(peer, "peer1"),
        _ => panic!("Expected RoundRobin variant"),
    }

    let result = LoadBalancerStrategy::from_str("FAILOVER(peer2)");
    assert!(result.is_some());
    match result.unwrap() {
        LoadBalancerStrategy::FailOver(peer) => assert_eq!(peer, "peer2"),
        _ => panic!("Expected FailOver variant"),
    }

    let result = LoadBalancerStrategy::from_str("RANDOM(peer3)");
    assert!(result.is_some());
    match result.unwrap() {
        LoadBalancerStrategy::Random(peer) => assert_eq!(peer, "peer3"),
        _ => panic!("Expected Random variant"),
    }
}

#[test]
fn test_load_balancer_strategy_round_robin_with_semicolons() {
    // round-robin argument containing semicolons (peer list inside)
    let result = LoadBalancerStrategy::from_str("round-robin(peer1;peer2;peer3)");
    assert!(result.is_some());
    match result.unwrap() {
        LoadBalancerStrategy::RoundRobin(arg) => assert_eq!(arg, "peer1;peer2;peer3"),
        _ => panic!("Expected RoundRobin variant"),
    }
}

#[test]
fn test_load_balancer_strategy_failover_with_semicolons() {
    // fail-over argument containing semicolons (fallback chain)
    let result = LoadBalancerStrategy::from_str("failover(primary;secondary;tertiary)");
    assert!(result.is_some());
    match result.unwrap() {
        LoadBalancerStrategy::FailOver(arg) => assert_eq!(arg, "primary;secondary;tertiary"),
        _ => panic!("Expected FailOver variant"),
    }
}

#[test]
fn test_load_balancer_strategy_round_robin_embedded_failover() {
    // round-robin with an embedded failover expression as its argument
    let result = LoadBalancerStrategy::from_str("round-robin(failover(peer1))");
    assert!(result.is_some());
    match result.unwrap() {
        LoadBalancerStrategy::RoundRobin(arg) => assert_eq!(arg, "failover(peer1)"),
        _ => panic!("Expected RoundRobin variant"),
    }
}

#[test]
fn test_load_balancer_strategy_failover_embedded_round_robin() {
    // fail-over with an embedded round-robin expression as its argument
    let result = LoadBalancerStrategy::from_str("failover(round-robin(peer1))");
    assert!(result.is_some());
    match result.unwrap() {
        LoadBalancerStrategy::FailOver(arg) => {
            LoadBalancerStrategy::from_str(&arg)
                .map(|inner| match inner {
                    LoadBalancerStrategy::RoundRobin(peer) => assert_eq!(peer, "peer1"),
                    _ => panic!("Expected RoundRobin variant inside FailOver"),
                })
                .unwrap();
        }
        _ => panic!("Expected FailOver variant"),
    }
}

#[test]
fn test_load_balancer_strategy_round_robin_embedded_random() {
    // round-robin with an embedded random expression
    let result = LoadBalancerStrategy::from_str("rr(random(pool1))");
    assert!(result.is_some());
    match result.unwrap() {
        LoadBalancerStrategy::RoundRobin(arg) => {
            LoadBalancerStrategy::from_str(&arg)
                .map(|inner| match inner {
                    LoadBalancerStrategy::Random(peer) => assert_eq!(peer, "pool1"),
                    _ => panic!("Expected Random variant inside RoundRobin"),
                })
                .unwrap();
        }
        _ => panic!("Expected RoundRobin variant"),
    }
}

#[test]
fn test_load_balancer_strategy_failover_embedded_with_semicolons() {
    // fail-over containing embedded round-robin with multiple peers
    let result = LoadBalancerStrategy::from_str("fo(rr(peer1;peer2))");
    assert!(result.is_some());
    match result.unwrap() {
        LoadBalancerStrategy::FailOver(arg) => {
            LoadBalancerStrategy::from_str(&arg)
                .map(|inner| match inner {
                    LoadBalancerStrategy::RoundRobin(peers) => assert_eq!(peers, "peer1;peer2"),
                    _ => panic!("Expected RoundRobin variant inside FailOver"),
                })
                .unwrap();
        }
        _ => panic!("Expected FailOver variant"),
    }
}

#[test]
fn test_load_balancer_strategy_value_with_embedded_strategies() {
    // semicolon-separated value where individual entries look like strategies
    // Note: since this starts with "round-robin(" and ends with ')', the first
    // splitn captures everything after the first '(' and strips the trailing ')'
    let result = LoadBalancerStrategy::from_str("round-robin(peer1,peer3);failover(peer2,peer4)");
    assert!(result.is_some());
    match result.unwrap() {
        LoadBalancerStrategy::Value(arg) => {
            assert_eq!(arg, ["round-robin(peer1,peer3)", "failover(peer2,peer4)"]);
        }
        _ => panic!("Expected Value variant (greedy match)"),
    }
}

#[test]
fn test_listen_address_from_str_sctp_ipv6_loopback() {
    let addr = ListenAddress::from_str("sctp://[::1]:5868").unwrap();
    assert_eq!(addr.protocol, "sctp");
    assert_eq!(addr.port, 5868);
    assert_eq!(addr.hosts, vec!["[::1]".to_string()]);
    assert!(addr.parameters.is_none());
}

#[test]
fn test_listen_address_from_str_sctp_ipv6_multiple_hosts() {
    let addr = ListenAddress::from_str("sctp://[2001:db8::1],[2001:db8::2]:5868").unwrap();
    assert_eq!(addr.protocol, "sctp");
    assert_eq!(addr.port, 5868);
    assert_eq!(
        addr.hosts,
        vec!["[2001:db8::1]".to_string(), "[2001:db8::2]".to_string()]
    );
    assert!(addr.parameters.is_none());
}

#[test]
fn test_listen_address_from_str_tcp_ipv6_with_parameters() {
    let addr = ListenAddress::from_str("tcp://[::1]:3868?tls=true").unwrap();
    assert_eq!(addr.protocol, "tcp");
    assert_eq!(addr.port, 3868);
    assert_eq!(addr.hosts, vec!["[::1]".to_string()]);
    let params = addr.parameters.unwrap();
    assert_eq!(params.get("tls"), Some(&"true".to_string()));
}

#[test]
fn test_listen_address_from_str_invalid_no_protocol() {
    let result = ListenAddress::from_str("127.0.0.1:3868");
    assert!(result.is_err());
}

#[test]
fn test_listen_address_from_str_invalid_no_port() {
    let result = ListenAddress::from_str("tcp://127.0.0.1");
    assert!(result.is_err());
}

#[test]
fn test_listen_address_from_str_invalid_port() {
    let result = ListenAddress::from_str("tcp://127.0.0.1:notaport");
    assert!(result.is_err());
}
