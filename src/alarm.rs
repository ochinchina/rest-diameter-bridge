use chrono::{DateTime, Utc};
use log::{error, info};
use rusqlite::{Connection as SqliteConnection, params};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::Mutex;

/// The severity level of a Diameter peer alarm.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "UPPERCASE")]
pub enum AlarmSeverity {
    Critical,
    Major,
    Minor,
    Warning,
    Clear,
}

/// Represents a Diameter peer connectivity alarm with full identity and timing information.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Alarm {
    pub alarm_id: String,
    pub severity: AlarmSeverity,
    pub peer_address: String,
    pub diameter_host: String,
    pub diameter_realm: String,
    pub description: String,
    pub raised_at: DateTime<Utc>,
}

impl Alarm {
    /// Creates a new `Alarm`.
    ///
    /// # Arguments
    /// * `peer_address` - The network address of the remote Diameter peer.
    /// * `diameter_host` - The Diameter identity (Origin-Host) of the peer.
    /// * `diameter_realm` - The Diameter realm of the peer.
    /// * `severity` - The alarm severity level.
    /// * `description` - A human-readable description of the alarm condition.
    pub fn new(
        peer_address: &str,
        diameter_host: &str,
        diameter_realm: &str,
        severity: AlarmSeverity,
        description: &str,
    ) -> Self {
        Alarm {
            alarm_id: format!("DIAMETER_PEER_{}@{}", diameter_host, peer_address),
            severity,
            peer_address: peer_address.to_string(),
            diameter_host: diameter_host.to_string(),
            diameter_realm: diameter_realm.to_string(),
            description: description.to_string(),
            raised_at: Utc::now(),
        }
    }
}

/// In-memory + SQLite backed alarm store
#[derive(Clone)]
pub struct AlarmStore {
    active_alarms: Arc<Mutex<HashMap<String, Alarm>>>,
    db: Arc<Mutex<SqliteConnection>>,
}

impl AlarmStore {
    /// Opens (or creates) the SQLite alarm database at `db_path`, creates the required tables
    /// if they do not exist, and loads any previously persisted active alarms into memory.
    ///
    /// # Arguments
    /// * `db_path` - Filesystem path to the SQLite database file.
    ///
    /// # Returns
    /// * `Ok(AlarmStore)` on success.
    /// * `Err(String)` if the database cannot be opened or initialised.
    pub fn new(db_path: &str) -> Result<Self, String> {
        let conn = SqliteConnection::open(db_path)
            .map_err(|e| format!("Failed to open alarm database at {}: {}", db_path, e))?;

        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS active_alarms (
                alarm_id TEXT PRIMARY KEY,
                severity TEXT NOT NULL,
                peer_address TEXT NOT NULL,
                diameter_host TEXT NOT NULL,
                diameter_realm TEXT NOT NULL,
                description TEXT NOT NULL,
                raised_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS alarm_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                alarm_id TEXT NOT NULL,
                severity TEXT NOT NULL,
                peer_address TEXT NOT NULL,
                diameter_host TEXT NOT NULL,
                diameter_realm TEXT NOT NULL,
                description TEXT NOT NULL,
                timestamp TEXT NOT NULL
            );",
        )
        .map_err(|e| format!("Failed to initialize alarm tables: {}", e))?;

        // Load active alarms from DB into memory
        let mut active_alarms = HashMap::new();
        {
            let mut stmt = conn
                .prepare("SELECT alarm_id, severity, peer_address, diameter_host, diameter_realm, description, raised_at FROM active_alarms")
                .map_err(|e| format!("Failed to prepare statement: {}", e))?;
            let rows = stmt
                .query_map([], |row| {
                    let severity_str: String = row.get(1)?;
                    let severity = match severity_str.as_str() {
                        "CRITICAL" => AlarmSeverity::Critical,
                        "MAJOR" => AlarmSeverity::Major,
                        "MINOR" => AlarmSeverity::Minor,
                        "WARNING" => AlarmSeverity::Warning,
                        _ => AlarmSeverity::Major,
                    };
                    let raised_at_str: String = row.get(6)?;
                    let raised_at = DateTime::parse_from_rfc3339(&raised_at_str)
                        .map(|dt| dt.with_timezone(&Utc))
                        .unwrap_or_else(|_| Utc::now());
                    Ok(Alarm {
                        alarm_id: row.get(0)?,
                        severity,
                        peer_address: row.get(2)?,
                        diameter_host: row.get(3)?,
                        diameter_realm: row.get(4)?,
                        description: row.get(5)?,
                        raised_at,
                    })
                })
                .map_err(|e| format!("Failed to load active alarms: {}", e))?;

            for row in rows {
                if let Ok(alarm) = row {
                    active_alarms.insert(alarm.alarm_id.clone(), alarm);
                }
            }
        }

        info!(
            "AlarmStore initialized with {} active alarms from database",
            active_alarms.len()
        );

        Ok(AlarmStore {
            active_alarms: Arc::new(Mutex::new(active_alarms)),
            db: Arc::new(Mutex::new(conn)),
        })
    }

    /// Persists the alarm to the database and records it in the active alarm set.
    pub async fn raise(&self, alarm: Alarm) {
        let alarm_id = alarm.alarm_id.clone();
        {
            let db = self.db.lock().await;

            // Insert into DB

            if let Err(e) = db.execute(
                "INSERT OR REPLACE INTO active_alarms (alarm_id, severity, peer_address, diameter_host, diameter_realm, description, raised_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                params![
                    alarm.alarm_id,
                    alarm.severity.as_str(),
                    alarm.peer_address,
                    alarm.diameter_host,
                    alarm.diameter_realm,
                    alarm.description,
                    alarm.raised_at.to_rfc3339(),
                ],
            ) {
                error!("Failed to insert alarm into database: {}", e);
            }
            if let Err(e) = db.execute(
                "INSERT INTO alarm_history (alarm_id, severity, peer_address, diameter_host, diameter_realm, description, timestamp) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                params![
                    alarm.alarm_id,
                    alarm.severity.as_str(),
                    alarm.peer_address,
                    alarm.diameter_host,
                    alarm.diameter_realm,
                    alarm.description,
                    alarm.raised_at.to_rfc3339(),
                ],
            ) {
                error!("Failed to insert alarm history: {}", e);
            }
        }

        // Insert into memory
        {
            let mut alarms = self.active_alarms.lock().await;
            alarms.insert(alarm_id.clone(), alarm);
        }

        info!("Alarm raised: {}", alarm_id);
    }

    /// Removes the alarm identified by `alarm_id` from the active set and records a clear event.
    pub async fn clear(&self, alarm_id: &str) {
        let db = self.db.lock().await;

        // Remove from DB
        {
            if let Err(e) = db.execute(
                "DELETE FROM active_alarms WHERE alarm_id = ?1",
                params![alarm_id],
            ) {
                error!("Failed to delete alarm from database: {}", e);
            }
            if let Err(e) = db.execute(
                "INSERT INTO alarm_history (alarm_id, severity, peer_address, diameter_host, diameter_realm, description, timestamp) VALUES (?1, 'CLEAR', '', '', '', 'Alarm cleared', ?2)",
                params![alarm_id, Utc::now().to_rfc3339()],
            ) {
                error!("Failed to insert clear into alarm history: {}", e);
            }
        }

        // Remove from memory
        {
            let mut alarms = self.active_alarms.lock().await;
            alarms.remove(alarm_id);
        }

        info!("Alarm cleared: {}", alarm_id);
    }

    pub async fn get_active_alarms(&self) -> Vec<Alarm> {
        self.active_alarms.lock().await.values().cloned().collect()
    }

    pub async fn get_alarm(&self, alarm_id: &str) -> Option<Alarm> {
        self.active_alarms.lock().await.get(alarm_id).cloned()
    }

    /// Returns `true` if an alarm with the given ID is currently active.
    pub async fn is_active(&self, alarm_id: &str) -> bool {
        self.active_alarms.lock().await.contains_key(alarm_id)
    }
}

/// Sends alarms to a remote web server and stores them locally
#[derive(Clone)]
pub struct AlarmSender {
    url: Option<String>,
    client: reqwest::Client,
    store: AlarmStore,
}

impl AlarmSender {
    /// Creates a new `AlarmSender`.
    ///
    /// # Arguments
    /// * `url` - Optional URL of the remote alarm manager endpoint; if `None` alarms are only stored locally.
    /// * `store` - The [`AlarmStore`] used for persistence and in-memory tracking.
    /// * `cert_file` - Optional path to a PEM client certificate for mTLS.
    /// * `key_file` - Optional path to the corresponding private key file.
    /// * `ca_cert_file` - Optional path to a PEM CA certificate for server verification.
    pub fn new(
        url: Option<String>,
        store: AlarmStore,
        cert_file: Option<String>,
        key_file: Option<String>,
        ca_cert_file: Option<String>,
    ) -> Self {
        let client = Self::build_client(
            cert_file.as_deref().unwrap_or_default(),
            key_file.as_deref().unwrap_or_default(),
            ca_cert_file.as_deref().unwrap_or_default(),
        )
        .unwrap_or_else(|e| {
            error!(
                "Failed to build TLS client for alarm sender: {}. Falling back to default client.",
                e
            );
            reqwest::Client::new()
        });

        AlarmSender { url, client, store }
    }

    fn build_client(
        cert_path: &str,
        key_path: &str,
        ca_cert_path: &str,
    ) -> Result<reqwest::Client, String> {
        use std::fs;

        let mut builder = reqwest::Client::builder();

        // Add CA certificate for server verification
        if !ca_cert_path.is_empty() {
            if let Ok(ca_pem) = fs::read(ca_cert_path) {
                let ca_cert = reqwest::tls::Certificate::from_pem(&ca_pem)
                    .map_err(|e| format!("Failed to parse CA cert '{}': {}", ca_cert_path, e))?;
                builder = builder.add_root_certificate(ca_cert);
            } else {
                return Err(format!("Failed to read CA cert file '{}'", ca_cert_path));
            }
        }

        // Add client identity for mTLS
        if !cert_path.is_empty() && !key_path.is_empty() {
            let cert_pem = fs::read(cert_path)
                .map_err(|e| format!("Failed to read cert file '{}': {}", cert_path, e))?;
            let key_pem = fs::read(key_path)
                .map_err(|e| format!("Failed to read key file '{}': {}", key_path, e))?;

            let mut identity_pem = cert_pem;
            identity_pem.extend_from_slice(&key_pem);

            let identity = reqwest::tls::Identity::from_pem(&identity_pem)
                .map_err(|e| format!("Failed to build TLS identity: {}", e))?;
            builder = builder.identity(identity);
        }

        builder
            .build()
            .map_err(|e| format!("Failed to build reqwest client: {}", e))
    }

    /// Returns a reference to the underlying [`AlarmStore`].
    pub fn get_store(&self) -> &AlarmStore {
        &self.store
    }

    /// Raises a Major-severity alarm for the given peer and forwards it to the remote alarm manager.
    pub async fn raise_alarm(
        &self,
        peer_address: &str,
        diameter_host: &str,
        diameter_realm: &str,
        description: &str,
    ) {
        let alarm = Alarm::new(
            peer_address,
            diameter_host,
            diameter_realm,
            AlarmSeverity::Major,
            description,
        );
        self.store.raise(alarm.clone()).await;
        self.send_alarm(&alarm).await;
    }

    /// Clears the alarm for the given peer and forwards a Clear event to the remote alarm manager.
    pub async fn clear_alarm(&self, peer_address: &str, diameter_host: &str, diameter_realm: &str) {
        let alarm = Alarm::new(
            peer_address,
            diameter_host,
            diameter_realm,
            AlarmSeverity::Clear,
            "Connection to diameter peer established",
        );
        self.store.clear(&alarm.alarm_id).await;
        self.send_alarm(&alarm).await;
    }

    async fn send_alarm(&self, alarm: &Alarm) {
        let url = match &self.url {
            Some(u) => u,
            None => return,
        };
        info!("Sending alarm to {}: {:?}", url, alarm);
        match self
            .client
            .post(url)
            .header("Content-Type", "application/json")
            .json(alarm)
            .send()
            .await
        {
            Ok(response) => {
                let status = response.status().as_u16();
                if status >= 200 && status < 400 {
                    info!(
                        "Alarm sent successfully for peer {} ({}): HTTP {}",
                        alarm.peer_address,
                        alarm.severity.as_str(),
                        status
                    );
                } else {
                    error!(
                        "Failed to send alarm for peer {}: HTTP {}",
                        alarm.peer_address, status
                    );
                }
            }
            Err(e) => {
                error!(
                    "Failed to send alarm for peer {}: {}",
                    alarm.peer_address, e
                );
            }
        }
    }
}

impl AlarmSeverity {
    pub fn as_str(&self) -> &str {
        match self {
            AlarmSeverity::Critical => "CRITICAL",
            AlarmSeverity::Major => "MAJOR",
            AlarmSeverity::Minor => "MINOR",
            AlarmSeverity::Warning => "WARNING",
            AlarmSeverity::Clear => "CLEAR",
        }
    }
}
