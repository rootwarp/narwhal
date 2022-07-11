// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use crate::{
    metrics::{Metrics, PrimaryNetworkMetrics},
    BoundedExecutor, CancelHandler, RetryConfig, MAX_TASK_CONCURRENCY,
};
use crypto::traits::VerifyingKey;
use futures::FutureExt;
use multiaddr::Multiaddr;
use rand::{prelude::SliceRandom as _, rngs::SmallRng, SeedableRng as _};
use std::collections::HashMap;
use tokio::{runtime::Handle, task::JoinHandle};
use tonic::transport::Channel;
use types::{
    BincodeEncodedPayload, PrimaryMessage, PrimaryToPrimaryClient, PrimaryToWorkerClient,
    PrimaryWorkerMessage,
};

pub struct PrimaryNetwork {
    clients: HashMap<Multiaddr, PrimaryToPrimaryClient<Channel>>,
    config: mysten_network::config::Config,
    retry_config: RetryConfig,
    /// Small RNG just used to shuffle nodes and randomize connections (not crypto related).
    rng: SmallRng,
    executor: BoundedExecutor,
    metrics: Option<Metrics<PrimaryNetworkMetrics>>,
}

impl Default for PrimaryNetwork {
    fn default() -> Self {
        let retry_config = RetryConfig {
            // Retry for forever
            retrying_max_elapsed_time: None,
            ..Default::default()
        };

        Self {
            clients: Default::default(),
            config: Default::default(),
            retry_config,
            rng: SmallRng::from_entropy(),
            executor: BoundedExecutor::new(MAX_TASK_CONCURRENCY, Handle::current()),
            metrics: None,
        }
    }
}

impl PrimaryNetwork {
    pub fn new(metrics: Metrics<PrimaryNetworkMetrics>) -> Self {
        Self {
            metrics: Some(Metrics::from(metrics, "primary".to_string())),
            ..Default::default()
        }
    }

    fn client(&mut self, address: Multiaddr) -> PrimaryToPrimaryClient<Channel> {
        self.clients
            .entry(address.clone())
            .or_insert_with(|| Self::create_client(&self.config, address))
            .clone()
    }

    fn create_client(
        config: &mysten_network::config::Config,
        address: Multiaddr,
    ) -> PrimaryToPrimaryClient<Channel> {
        //TODO don't panic here if address isn't supported
        let channel = config.connect_lazy(&address).unwrap();
        PrimaryToPrimaryClient::new(channel)
    }

    pub async fn send<T: VerifyingKey>(
        &mut self,
        address: Multiaddr,
        message: &PrimaryMessage<T>,
    ) -> CancelHandler<()> {
        let message =
            BincodeEncodedPayload::try_from(message).expect("Failed to serialize payload");
        let handler = self.send_message(address, message).await;

        self.update_metrics();

        handler
    }

    async fn send_message(
        &mut self,
        address: Multiaddr,
        message: BincodeEncodedPayload,
    ) -> CancelHandler<()> {
        let client = self.client(address);
        let handle = self
            .executor
            .spawn(
                self.retry_config
                    .retry(move || {
                        let mut client = client.clone();
                        let message = message.clone();
                        async move { client.send_message(message).await.map_err(Into::into) }
                    })
                    .map(|response| {
                        response.expect("we retry forever so this shouldn't fail");
                    }),
            )
            .await;

        CancelHandler(handle)
    }

    pub async fn broadcast<T: VerifyingKey>(
        &mut self,
        addresses: Vec<Multiaddr>,
        message: &PrimaryMessage<T>,
    ) -> Vec<CancelHandler<()>> {
        let message =
            BincodeEncodedPayload::try_from(message).expect("Failed to serialize payload");
        let mut handlers = Vec::new();
        for address in addresses {
            let handle = self.send_message(address, message.clone()).await;
            handlers.push(handle);
        }

        self.update_metrics();

        handlers
    }

    pub async fn unreliable_send<T: VerifyingKey>(
        &mut self,
        address: Multiaddr,
        message: &PrimaryMessage<T>,
    ) -> JoinHandle<()> {
        let message =
            BincodeEncodedPayload::try_from(message).expect("Failed to serialize payload");
        let mut client = self.client(address);
        let handler = self
            .executor
            .spawn(async move {
                let _ = client.send_message(message).await;
            })
            .await;

        self.update_metrics();

        handler
    }

    /// Pick a few addresses at random (specified by `nodes`) and try (best-effort) to send the
    /// message only to them. This is useful to pick nodes with whom to sync.
    pub async fn unreliable_broadcast<T: VerifyingKey>(
        &mut self,
        addresses: Vec<Multiaddr>,
        message: &PrimaryMessage<T>,
    ) -> Vec<JoinHandle<()>> {
        let message =
            BincodeEncodedPayload::try_from(message).expect("Failed to serialize payload");
        let mut handlers = Vec::new();
        for address in addresses {
            let handle = {
                let mut client = self.client(address);
                let message = message.clone();
                self.executor
                    .spawn(async move {
                        let _ = client.send_message(message).await;
                    })
                    .await
            };
            handlers.push(handle);
        }

        self.update_metrics();

        handlers
    }

    /// Pick a few addresses at random (specified by `nodes`) and try (best-effort) to send the
    /// message only to them. This is useful to pick nodes with whom to sync.
    pub async fn lucky_broadcast<T: VerifyingKey>(
        &mut self,
        mut addresses: Vec<Multiaddr>,
        message: &PrimaryMessage<T>,
        nodes: usize,
    ) -> Vec<JoinHandle<()>> {
        addresses.shuffle(&mut self.rng);
        addresses.truncate(nodes);
        let message =
            BincodeEncodedPayload::try_from(message).expect("Failed to serialize payload");
        let mut handlers = Vec::new();
        for address in addresses {
            let handle = {
                let mut client = self.client(address);
                let message = message.clone();
                self.executor
                    .spawn(async move {
                        let _ = client.send_message(message).await;
                    })
                    .await
            };
            handlers.push(handle);
        }

        self.update_metrics();

        handlers
    }

    fn update_metrics(&self) {
        if let Some(m) = &self.metrics {
            m.set_network_concurrent_tasks(self.executor.current_running() as i64);
        }
    }
}

pub struct PrimaryToWorkerNetwork {
    clients: HashMap<Multiaddr, PrimaryToWorkerClient<Channel>>,
    config: mysten_network::config::Config,
    executor: BoundedExecutor,
    metrics: Option<Metrics<PrimaryNetworkMetrics>>,
}

impl Default for PrimaryToWorkerNetwork {
    fn default() -> Self {
        Self {
            clients: Default::default(),
            config: Default::default(),
            executor: BoundedExecutor::new(MAX_TASK_CONCURRENCY, Handle::current()),
            metrics: None,
        }
    }
}

impl PrimaryToWorkerNetwork {
    pub fn new(metrics: Metrics<PrimaryNetworkMetrics>) -> Self {
        Self {
            metrics: Some(Metrics::from(metrics, "primary_to_worker".to_string())),
            ..Default::default()
        }
    }

    fn client(&mut self, address: Multiaddr) -> PrimaryToWorkerClient<Channel> {
        self.clients
            .entry(address.clone())
            .or_insert_with(|| Self::create_client(&self.config, address))
            .clone()
    }

    fn create_client(
        config: &mysten_network::config::Config,
        address: Multiaddr,
    ) -> PrimaryToWorkerClient<Channel> {
        //TODO don't panic here if address isn't supported
        let channel = config.connect_lazy(&address).unwrap();
        PrimaryToWorkerClient::new(channel)
    }

    pub async fn send<T: VerifyingKey>(
        &mut self,
        address: Multiaddr,
        message: &PrimaryWorkerMessage<T>,
    ) -> JoinHandle<()> {
        let message =
            BincodeEncodedPayload::try_from(message).expect("Failed to serialize payload");
        let mut client = self.client(address);
        let handler = self
            .executor
            .spawn(async move {
                let _ = client.send_message(message).await;
            })
            .await;

        self.update_metrics();

        handler
    }

    pub async fn broadcast<T: VerifyingKey>(
        &mut self,
        addresses: Vec<Multiaddr>,
        message: &PrimaryWorkerMessage<T>,
    ) -> Vec<JoinHandle<()>> {
        let message =
            BincodeEncodedPayload::try_from(message).expect("Failed to serialize payload");
        let mut handlers = Vec::new();
        for address in addresses {
            let handle = {
                let mut client = self.client(address);
                let message = message.clone();
                self.executor
                    .spawn(async move {
                        let _ = client.send_message(message).await;
                    })
                    .await
            };
            handlers.push(handle);
        }

        self.update_metrics();

        handlers
    }

    fn update_metrics(&self) {
        if let Some(m) = &self.metrics {
            m.set_network_concurrent_tasks(self.executor.current_running() as i64);
        }
    }
}
