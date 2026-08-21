use crate::transport::connection::Connection;
use std::sync::Arc;
use std::sync::atomic::AtomicUsize;
use tokio::sync::Mutex;

/// A thread-safe, ordered list of [`Connection`] handles shared across tasks.
#[derive(Clone)]
pub struct ConnectionList {
    connections: Arc<Mutex<Vec<Arc<Box<dyn Connection + Send + Sync>>>>>,
}

impl Default for ConnectionList {
    fn default() -> Self {
        ConnectionList::new(Vec::new())
    }
}

impl ConnectionList {
    /// Creates a new `ConnectionList` pre-populated with the given connections.
    pub fn new(connections: Vec<Arc<Box<dyn Connection + Send + Sync>>>) -> Self {
        ConnectionList {
            connections: Arc::new(Mutex::new(connections)),
        }
    }

    /// Appends a connection to the end of the list.
    /// # Arguments
    /// * `connection` - The connection to add.
    pub async fn add_connection(&self, connection: Arc<Box<dyn Connection + Send + Sync>>) {
        let mut connections = self.connections.lock().await;
        connections.push(connection);
    }

    /// Removes the connection that points to the same allocation as `connection`.
    /// # Arguments
    /// * `connection` - The connection to remove.
    pub async fn remove_connection(&self, connection: Arc<Box<dyn Connection + Send + Sync>>) {
        let mut connections = self.connections.lock().await;
        connections.retain(|conn| !Arc::ptr_eq(conn, &connection));
    }

    /// Returns the number of connections currently in the list (blocks until the lock is held).
    pub fn len(&self) -> usize {
        let connections = futures::executor::block_on(self.connections.lock());
        connections.len()
    }

    /// Returns `true` if the list contains no connections.
    pub async fn is_empty(&self) -> bool {
        let connections = self.connections.lock().await;
        connections.is_empty()
    }

    /// Returns the connection at `index`, or `None` if the index is out of bounds.
    /// # Arguments
    /// * `index` - The index of the connection to retrieve.
    /// Returns
    /// * `Some(Arc<Box<dyn Connection + Send + Sync>>)` if the index is valid, or `None` if it is out of bounds.
    pub async fn get_connection(
        &self,
        index: usize,
    ) -> Option<Arc<Box<dyn Connection + Send + Sync>>> {
        let connections = self.connections.lock().await;
        connections.get(index).cloned()
    }

    /// Returns a snapshot of all connections currently in the list.
    /// Blocks until the lock is held.
    /// Returns
    /// * `Vec<Arc<Box<dyn Connection + Send + Sync>>>` - A vector containing all connections in the list.
    pub async fn get_connections(&self) -> Vec<Arc<Box<dyn Connection + Send + Sync>>> {
        let conn_list = self.connections.lock().await;
        conn_list.clone()
    }

    /// Returns an owned iterator over a snapshot of the connections (blocks until the lock is held).
    pub fn iter(&self) -> Box<dyn Iterator<Item = Arc<Box<dyn Connection + Send + Sync>>> + Send> {
        let connections = futures::executor::block_on(self.connections.lock());
        Box::new(connections.clone().into_iter())
    }
}

/// An [`Iterator`] over the leaf connections in a [`ConnectionList`], transparently
/// expanding any container connections (round-robin, failover, etc.) encountered along the way.
pub struct ConnectionIterator {
    connections: Arc<ConnectionList>,
    index: AtomicUsize,
    sub_iter: Option<Box<dyn Iterator<Item = Arc<Box<dyn Connection + Send + Sync>>> + Send>>,
    tried_times: AtomicUsize,
}

impl ConnectionIterator {
    /// Creates a new `ConnectionIterator` starting at the given `index`.
    pub fn new(connections: Arc<ConnectionList>, index: AtomicUsize) -> Self {
        ConnectionIterator {
            connections,
            index,
            sub_iter: None, // Initialize sub_iter with None
            tried_times: AtomicUsize::new(0),
        }
    }

    fn get_next(
        connections: &Vec<Arc<Box<dyn Connection + Send + Sync>>>,
        index: &AtomicUsize,
    ) -> Option<Arc<Box<dyn Connection + Send + Sync>>> {
        let n = connections.len();
        if n == 0 {
            return None;
        }
        let i = index.load(std::sync::atomic::Ordering::Relaxed);
        let conn = connections.get(i % n).cloned();
        index.store((i + 1) % n, std::sync::atomic::Ordering::Relaxed);

        conn
    }
}

impl Iterator for ConnectionIterator {
    type Item = Arc<Box<dyn Connection + Send + Sync>>;

    fn next(&mut self) -> Option<Self::Item> {
        let connections = futures::executor::block_on(self.connections.get_connections());
        let n = connections.len();
        if n == 0 || self.tried_times.load(std::sync::atomic::Ordering::Relaxed) >= n {
            return None;
        }

        // If we have an active sub_iter, drain it first before advancing the outer index
        if let Some(sub_iter) = &mut self.sub_iter {
            if let Some(sub_conn) = sub_iter.next() {
                return Some(sub_conn);
            } else {
                // Sub-iterator exhausted, move on to the next outer connection
                self.sub_iter = None;
                self.tried_times
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                if self.tried_times.load(std::sync::atomic::Ordering::Relaxed) >= n {
                    return None;
                }
            }
        }

        loop {
            match Self::get_next(&connections, &self.index) {
                Some(conn) => {
                    if conn.is_container() {
                        self.sub_iter = conn.iter();
                        if let Some(sub_iter) = &mut self.sub_iter {
                            if let Some(sub_conn) = sub_iter.next() {
                                return Some(sub_conn);
                            } else {
                                // Empty container, count it and continue
                                self.sub_iter = None;
                                self.tried_times
                                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                                if self.tried_times.load(std::sync::atomic::Ordering::Relaxed) >= n
                                {
                                    return None;
                                }
                                continue;
                            }
                        } else {
                            // iter() returned None — empty container, skip it
                            self.tried_times
                                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                            if self.tried_times.load(std::sync::atomic::Ordering::Relaxed) >= n {
                                return None;
                            }
                            continue;
                        }
                    } else {
                        self.tried_times
                            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                        return Some(conn);
                    }
                }
                None => return None,
            }
        }
    }
}
