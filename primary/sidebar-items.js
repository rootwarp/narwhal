initSidebarItems({"constant":[["CHANNEL_CAPACITY","The default channel capacity for each channel of the primary."]],"enum":[["BlockCommand",""],["BlockRemoverCommand",""],["PrimaryWorkerMessage","The messages sent by the primary to its workers."],["WorkerPrimaryError",""],["WorkerPrimaryMessage","The messages sent by the workers to their primary."]],"mod":[["block_synchronizer",""]],"struct":[["BlockRemover","BlockRemover is responsible for removing blocks identified by their certificate id (digest) from across our system. On high level It will make sure that the DAG is updated, internal storage where there certificates and headers are stored, and the corresponding batches as well."],["BlockWaiter","BlockWaiter is responsible for fetching the block data from the downstream worker nodes. A block is basically the aggregate of batches of transactions for a given certificate."],["DeleteBatchMessage",""],["Primary",""]],"type":[["PayloadToken",""]]});