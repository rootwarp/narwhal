// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use prometheus::{default_registry, register_int_gauge_vec_with_registry, IntGaugeVec, Registry};
use std::sync::Arc;

pub trait NetworkMetrics {
    fn network_concurrent_tasks(&self) -> &IntGaugeVec;
}

#[derive(Clone, Debug)]
pub struct PrimaryNetworkMetrics {
    /// The number of tasks running
    pub network_concurrent_tasks: IntGaugeVec,
}

impl PrimaryNetworkMetrics {
    pub fn new(registry: &Registry) -> Self {
        Self {
            network_concurrent_tasks: register_int_gauge_vec_with_registry!(
                "primary_network_concurrent_tasks",
                "The number of concurrent tasks running in the network connector",
                &["module", "network"],
                registry
            )
            .unwrap(),
        }
    }
}

impl NetworkMetrics for PrimaryNetworkMetrics {
    fn network_concurrent_tasks(&self) -> &IntGaugeVec {
        &self.network_concurrent_tasks
    }
}

impl Default for PrimaryNetworkMetrics {
    fn default() -> Self {
        Self::new(default_registry())
    }
}

#[derive(Clone, Debug)]
pub struct WorkerNetworkMetrics {
    /// The number of tasks running
    pub network_concurrent_tasks: IntGaugeVec,
}

impl WorkerNetworkMetrics {
    pub fn new(registry: &Registry) -> Self {
        Self {
            network_concurrent_tasks: register_int_gauge_vec_with_registry!(
                "worker_network_concurrent_tasks",
                "The number of concurrent tasks running in the network connector",
                &["module", "network"],
                registry
            )
            .unwrap(),
        }
    }
}

impl NetworkMetrics for WorkerNetworkMetrics {
    fn network_concurrent_tasks(&self) -> &IntGaugeVec {
        &self.network_concurrent_tasks
    }
}

impl Default for WorkerNetworkMetrics {
    fn default() -> Self {
        Self::new(default_registry())
    }
}

pub struct Metrics<N: NetworkMetrics> {
    metrics_handler: Arc<N>,
    module_tag: String,
    network_type: String,
}

impl<N: NetworkMetrics> Metrics<N> {
    pub fn new(metrics_handler: Arc<N>, module_tag: String) -> Self {
        Self {
            metrics_handler,
            module_tag,
            network_type: "".to_string(),
        }
    }

    pub fn from(metrics: Metrics<N>, network_type: String) -> Metrics<N> {
        Metrics {
            metrics_handler: metrics.metrics_handler,
            module_tag: metrics.module_tag,
            network_type,
        }
    }

    pub fn set_network_concurrent_tasks(&self, value: i64) {
        self.metrics_handler
            .network_concurrent_tasks()
            .with_label_values(&[self.module_tag.as_str(), self.network_type.as_str()])
            .set(value);
    }
}

#[cfg(test)]
mod test {
    use crate::metrics::{Metrics, NetworkMetrics, PrimaryNetworkMetrics};
    use prometheus::Registry;
    use std::{collections::HashMap, sync::Arc};

    #[test]
    fn test_called_metrics() {
        // GIVEN
        let registry = Registry::new();
        let metrics = Metrics {
            metrics_handler: Arc::new(PrimaryNetworkMetrics::new(&registry)),
            module_tag: "demo_handler".to_string(),
            network_type: "primary".to_string(),
        };

        // WHEN update metrics
        metrics.set_network_concurrent_tasks(14);

        // THEN registry should be updated with expected tag
        let mut m = HashMap::new();
        m.insert("module", "demo_handler");
        m.insert("network", "primary");
        assert_eq!(
            metrics
                .metrics_handler
                .network_concurrent_tasks()
                .get_metric_with(&m)
                .unwrap()
                .get(),
            14
        );
    }
}
