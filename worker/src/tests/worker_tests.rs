// Copyright (c) 2021, Facebook, Inc. and its affiliates
// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0
use super::*;
use crate::common::{
    batch_digest, committee_with_base_port, keys, serialized_batch, temp_dir, transaction,
    WorkerToPrimaryMockServer, WorkerToWorkerMockServer,
};
use futures::StreamExt;
use primary::WorkerPrimaryMessage;
use store::rocks;
use types::{TransactionsClient, WorkerToWorkerClient};

#[tokio::test]
async fn handle_clients_transactions() {
    let (name, _) = keys().pop().unwrap();
    let id = 0;
    let committee = committee_with_base_port(11_000);
    let parameters = Parameters {
        batch_size: 200, // Two transactions.
        ..Parameters::default()
    };

    // Create a new test store.
    let db = rocks::DBMap::<BatchDigest, SerializedBatchMessage>::open(
        temp_dir(),
        None,
        Some("batches"),
    )
    .unwrap();
    let store = Store::new(db);

    // Spawn a `Worker` instance.
    Worker::spawn(name.clone(), id, committee.clone(), parameters, store);

    // Spawn a network listener to receive our batch's digest.
    let primary_address = committee.primary(&name).unwrap().worker_to_primary;
    let expected = bincode::serialize(&WorkerPrimaryMessage::OurBatch(batch_digest(), id)).unwrap();
    let mut handle = WorkerToPrimaryMockServer::spawn(primary_address);

    // Spawn enough workers' listeners to acknowledge our batches.
    let mut other_workers = Vec::new();
    for (_, addresses) in committee.others_workers(&name, &id) {
        let address = addresses.worker_to_worker;
        other_workers.push(WorkerToWorkerMockServer::spawn(address));
    }

    // Wait till other services have been able to start up
    tokio::task::yield_now().await;
    // Send enough transactions to create a batch.
    let address = committee.worker(&name, &id).unwrap().transactions;
    let mut client = TransactionsClient::connect(format!("http://{address}"))
        .await
        .unwrap();
    let txn = TransactionProto {
        transaction: Bytes::from(transaction()),
    };
    client.submit_transaction(txn.clone()).await.unwrap();
    client.submit_transaction(txn).await.unwrap();

    // Ensure the primary received the batch's digest (ie. it did not panic).
    assert_eq!(handle.recv().await.unwrap().payload, expected);
}

#[tokio::test]
async fn handle_client_batch_request() {
    let (name, _) = keys().pop().unwrap();
    let id = 0;
    let committee = committee_with_base_port(11_001);
    let parameters = Parameters {
        max_header_delay: 100_000, // Ensure no batches are created.
        ..Parameters::default()
    };

    // Create a new test store.
    let db = rocks::DBMap::<BatchDigest, SerializedBatchMessage>::open(
        temp_dir(),
        None,
        Some("batches"),
    )
    .unwrap();
    let store = Store::new(db);

    // Add a batch to the store.
    store.write(batch_digest(), serialized_batch()).await;

    // Spawn a `Worker` instance.
    Worker::spawn(name.clone(), id, committee.clone(), parameters, store);

    // Spawn a client to ask for batches and receive the reply.
    tokio::task::yield_now().await;
    let address = committee.worker(&name, &id).unwrap().worker_to_worker;
    let url = format!("http://{}", address);
    let mut client = WorkerToWorkerClient::connect(url).await.unwrap();

    // Send batch request.
    let digests = vec![batch_digest()];
    let message = ClientBatchRequest(digests);
    let mut stream = client
        .client_batch_request(BincodeEncodedPayload::try_from(&message).unwrap())
        .await
        .unwrap()
        .into_inner();

    // Wait for the reply and ensure it is as expected.
    let bytes = stream.next().await.unwrap().unwrap().payload;
    let expected = Bytes::from(serialized_batch());
    assert_eq!(bytes, expected);
}
