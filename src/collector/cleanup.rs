// SPDX-License-Identifier: MIT
// Copyright (c) 2025 Jesof

use crate::mikrotik::ConnectionPool;
use std::sync::Arc;
use std::time::Duration;

pub(super) async fn run_pool_cleanup(pool: Arc<ConnectionPool>) {
    super::run_schedule(Duration::from_secs(60), || pool.cleanup()).await;
}
