// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0
use crate::cluster::Cluster;
use std::time::Duration;

#[tokio::test]
async fn basic_cluster_setup() {
    let mut cluster = Cluster::new(None, None);

    // start the cluster will all the possible nodes
    cluster.start(None, None).await;

    // give some time for nodes to boostrap
    tokio::time::sleep(Duration::from_secs(2)).await;

    // fetch all the running authorities
    let authorities = cluster.authorities();

    assert_eq!(authorities.len(), 4);

    // fetch their workers transactions address
    for authority in cluster.authorities() {
        assert_eq!(authority.worker_transaction_addresses().len(), 4);
    }

    // now stop all authorities
    for id in 0..4 {
        cluster.stop_node(id);
    }

    tokio::time::sleep(Duration::from_secs(2)).await;

    // No authority should still run
    assert!(cluster.authorities().is_empty());
}
