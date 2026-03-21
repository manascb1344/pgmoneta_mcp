use pgmoneta_mcp::configuration::{
    CONFIG, Configuration, PgmonetaConfiguration, PgmonetaMcpConfiguration,
};
use pgmoneta_mcp::security::SecurityUtil;
use std::collections::HashMap;
use std::sync::Once;

static INIT_CONFIG: Once = Once::new();

pub fn init_config() {
    INIT_CONFIG.call_once(|| {
        let security: SecurityUtil = SecurityUtil::new();
        let master_key = security.load_master_key().expect("master key must exist");
        let encrypted = security
            .encrypt_to_base64_string(b"backup_pass", &master_key[..])
            .expect("password encryption should succeed");

        let mut admins: HashMap<String, String> = HashMap::new();
        admins.insert("backup_user".to_string(), encrypted);

        let config = Configuration {
            pgmoneta_mcp: PgmonetaMcpConfiguration {
                port: 8000,
                log_path: "pgmoneta_mcp.log".to_string(),
                log_level: "info".to_string(),
                log_type: "console".to_string(),
                log_line_prefix: "%Y-%m-%d %H:%M:%S".to_string(),
                log_mode: "append".to_string(),
                log_rotation_age: "0".to_string(),
            },
            pgmoneta: PgmonetaConfiguration {
                host: "127.0.0.1".to_string(),
                port: 5002,
                compression: "zstd".to_string(),
                encryption: "aes_256_cbc".to_string(),
            },
            admins,
            llm: None,
        };

        CONFIG
            .set(config)
            .expect("CONFIG should be initialized once");
    });
}
