use std::collections::HashMap;

pub struct FileChangeMonitor {
    file_last_changes: HashMap<String, std::time::SystemTime>,
    check_interval: std::time::Duration,
    last_check_time: std::time::SystemTime,
}

impl FileChangeMonitor {
    pub fn new(files: Vec<String>, check_interval: std::time::Duration) -> Self {
        let mut file_last_changes = HashMap::new();

        for file in files {
            if let Ok(metadata) = std::fs::metadata(&file) {
                if let Ok(modified_time) = metadata.modified() {
                    file_last_changes.insert(file, modified_time);
                }
            }
        }
        FileChangeMonitor {
            file_last_changes,
            check_interval,
            last_check_time: std::time::SystemTime::now(),
        }
    }

    pub fn update_file_change(&mut self) -> Vec<String> {
        if !self.is_time_to_check() {
            return Vec::new();
        }

        self.last_check_time = std::time::SystemTime::now();

        let mut changed_files = Vec::new();
        let files: Vec<String> = self.file_last_changes.keys().cloned().collect();

        for file_path in files {
            // Check if the file has been modified since the last check
            if let Ok(metadata) = std::fs::metadata(&file_path) {
                if let Ok(modified_time) = metadata.modified() {
                    if let Some(last_time) = self.file_last_changes.get(&file_path) {
                        if *last_time == modified_time {
                            continue; // File has not changed since last check
                        }
                    }

                    self.file_last_changes
                        .insert(file_path.to_string(), modified_time);

                    changed_files.push(file_path.to_string());
                }
            }
        }
        changed_files
    }

    fn is_time_to_check(&self) -> bool {
        self.last_check_time
            .elapsed()
            .unwrap_or(std::time::Duration::from_secs(
                self.check_interval.as_secs() + 1,
            ))
            >= self.check_interval
    }
}
