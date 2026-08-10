use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::Mutex;

use crate::avp::RedirectHostUsage;
use crate::{avp::AvpCode, command::Command};

#[derive(Debug, Clone)]
struct RedirectEntry {
    hosts: Vec<String>,
    expires_at: Option<Instant>,
}

impl RedirectEntry {
    fn is_expired(&self) -> bool {
        if let Some(expires_at) = self.expires_at {
            Instant::now() >= expires_at
        } else {
            false
        }
    }
}

#[derive(Debug, Clone)]
struct RedirectCaches {
    /// Key: session-id -> RedirectEntry (AllSession)
    session: HashMap<String, RedirectEntry>,
    /// Key: realm -> RedirectEntry (AllRealm)
    realm: HashMap<String, RedirectEntry>,
    /// Key: "realm:app_id" -> RedirectEntry (RealmAndApplication)
    realm_app: HashMap<String, RedirectEntry>,
    /// Key: app_id as string -> RedirectEntry (AllApplication)
    application: HashMap<String, RedirectEntry>,
    /// Key: destination-host -> RedirectEntry (AllHost)
    host: HashMap<String, RedirectEntry>,
    /// Key: user-name -> RedirectEntry (AllUser)
    user: HashMap<String, RedirectEntry>,
    /// The next time to clean up expired entries.
    next_cleanup_time: Instant,
    /// The interval at which to clean up expired entries.
    clean_interval: Duration,
}

impl RedirectCaches {
    fn new() -> Self {
        RedirectCaches {
            session: HashMap::new(),
            realm: HashMap::new(),
            realm_app: HashMap::new(),
            application: HashMap::new(),
            host: HashMap::new(),
            user: HashMap::new(),
            next_cleanup_time: Instant::now() + Duration::from_secs(30),
            clean_interval: Duration::from_secs(30),
        }
    }

    fn add_redirect(&mut self, answer: &Command) {
        self.remove_expired();

        let redirect_hosts: Vec<String> = answer
            .get_avps(AvpCode::RedirectHost as u32)
            .iter()
            .filter_map(|avp| avp.as_utf8_string())
            .collect();

        if redirect_hosts.is_empty() {
            return;
        }

        let usage = answer
            .get_redirect_host_usage()
            .unwrap_or(RedirectHostUsage::DontCache);

        if usage == RedirectHostUsage::DontCache {
            return;
        }

        let expires_at = answer
            .get_avp(AvpCode::RedirectMaxCacheTime as u32)
            .and_then(|avp| avp.as_unsigned32())
            .map(|seconds| Instant::now() + Duration::from_secs(seconds as u64));

        let entry = RedirectEntry {
            hosts: redirect_hosts,
            expires_at,
        };

        match usage {
            RedirectHostUsage::AllSession => {
                if let Some(session_id) = answer
                    .get_avp(AvpCode::SessionId as u32)
                    .and_then(|a| a.as_utf8_string())
                {
                    self.session.insert(session_id, entry);
                }
            }
            RedirectHostUsage::AllRealm => {
                if let Some(realm) = answer.get_destination_realm() {
                    self.realm.insert(realm, entry);
                }
            }
            RedirectHostUsage::RealmAndApplication => {
                if let Some(realm) = answer.get_destination_realm() {
                    let app_id = answer.get_application_id();
                    let key = format!("{}:{}", realm, app_id);
                    self.realm_app.insert(key, entry);
                }
            }
            RedirectHostUsage::AllApplication => {
                let app_id = answer.get_application_id();
                self.application.insert(app_id.to_string(), entry);
            }
            RedirectHostUsage::AllHost => {
                if let Some(host) = answer.get_destination_host() {
                    self.host.insert(host, entry);
                }
            }
            RedirectHostUsage::AllUser => {
                if let Some(user) = answer
                    .get_avp(AvpCode::UserName as u32)
                    .and_then(|a| a.as_utf8_string())
                {
                    self.user.insert(user, entry);
                }
            }
            RedirectHostUsage::DontCache => {}
        }
    }

    fn get_redirect(&mut self, request: &Command) -> Option<Vec<String>> {
        if let Some(session_id) = request
            .get_avp(AvpCode::SessionId as u32)
            .and_then(|a| a.as_utf8_string())
        {
            if let Some(hosts) = Self::lookup_in(&mut self.session, &session_id) {
                return Some(hosts);
            }
        }

        if let Some(realm) = request.get_destination_realm() {
            let app_id = request.get_application_id();
            let key = format!("{}:{}", realm, app_id);
            if let Some(hosts) = Self::lookup_in(&mut self.realm_app, &key) {
                return Some(hosts);
            }
        }

        if let Some(realm) = request.get_destination_realm() {
            if let Some(hosts) = Self::lookup_in(&mut self.realm, &realm) {
                return Some(hosts);
            }
        }

        let app_id = request.get_application_id();
        if let Some(hosts) = Self::lookup_in(&mut self.application, &app_id.to_string()) {
            return Some(hosts);
        }

        if let Some(dest_host) = request.get_destination_host() {
            if let Some(hosts) = Self::lookup_in(&mut self.host, &dest_host) {
                return Some(hosts);
            }
        }

        if let Some(user) = request
            .get_avp(AvpCode::UserName as u32)
            .and_then(|a| a.as_utf8_string())
        {
            if let Some(hosts) = Self::lookup_in(&mut self.user, &user) {
                return Some(hosts);
            }
        }

        None
    }

    fn lookup_in(map: &mut HashMap<String, RedirectEntry>, key: &str) -> Option<Vec<String>> {
        if let Some(entry) = map.get(key) {
            if entry.is_expired() {
                map.remove(key);
                return None;
            }
            return Some(entry.hosts.clone());
        }
        None
    }

    fn remove_expired(&mut self) {
        if self.next_cleanup_time > Instant::now() {
            return;
        }
        self.next_cleanup_time = Instant::now() + self.clean_interval;

        self.session.retain(|_, e| !e.is_expired());
        self.realm.retain(|_, e| !e.is_expired());
        self.realm_app.retain(|_, e| !e.is_expired());
        self.application.retain(|_, e| !e.is_expired());
        self.host.retain(|_, e| !e.is_expired());
        self.user.retain(|_, e| !e.is_expired());
    }
}

#[derive(Clone)]
/// Manages cached redirect host information based on Diameter Redirect-Host AVPs and their usage.
pub struct RedirectHostManager {
    caches: Arc<Mutex<RedirectCaches>>,
}

impl RedirectHostManager {
    pub fn new() -> Self {
        RedirectHostManager {
            caches: Arc::new(Mutex::new(RedirectCaches::new())),
        }
    }

    /// Extracts redirect information from a Diameter answer and caches according to Redirect-Host-Usage.
    /// # Arguments
    /// * `answer` - The Diameter answer command containing redirect information.
    pub async fn add_redirect(&self, answer: &Command) {
        self.caches.lock().await.add_redirect(answer);
    }

    /// Looks up a cached redirect host for the given request.
    /// Checks all cache levels in order: session, realm+app, realm, application, host, user.
    /// # Arguments
    /// * `request` - The Diameter request command for which to find a redirect host.
    /// # Returns
    /// * `Some(Vec<String>)` - A list of redirect hosts if a redirect is applicable.
    /// * `None` - If no redirect is applicable.
    pub async fn get_redirect(&self, request: &Command) -> Option<Vec<String>> {
        self.caches.lock().await.get_redirect(request)
    }
}
