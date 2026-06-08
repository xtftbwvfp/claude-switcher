use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine as _;
use chrono::{DateTime, Duration, Utc};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::{Mutex, OnceLock};
use std::thread;
use std::time::Duration as StdDuration;
use tauri::tray::{MouseButton, MouseButtonState, TrayIconEvent};
use tauri::{
    AppHandle, Manager, PhysicalPosition, Position, WebviewUrl, WebviewWindow, WebviewWindowBuilder,
};
use uuid::Uuid;

const KEYCHAIN_SERVICE: &str = "Claude Code-credentials";
// 早期 claude-switcher 误把 account 写成了 "Claude Code"，切号时顺手清理残留。
const LEGACY_KEYCHAIN_ACCOUNT: &str = "Claude Code";
// C2：store/备份里 keychain_password 落盘加密用的主密钥（32B AES-256），
// 单独存一个 Keychain 项里（service 固定，account=当前系统用户名）。
const STORE_KEY_KEYCHAIN_SERVICE: &str = "claude-switcher-store-key";
// C2：加密值前缀。格式为 "enc:v1:" + base64(nonce(12B) || ciphertext)。
// 不以此前缀开头的值一律当作旧明文（向后兼容），下次落盘时会被自动加密。
const ENC_PREFIX: &str = "enc:v1:";
const DEFAULT_CLASH_GROUP: &str = "Auto-Claude";
// 遥测去关联：注入进 ~/.claude/settings.json 的 "env" 的两个隐私开关 key（互斥）。
// - DISABLE_TELEMETRY=1：关掉 Claude Code 的遥测上报（推荐，副作用最小）。
// - CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC=1：连同所有非必要网络一起关
//   （最强，副作用：手动更新滞后 / 新模型滞后 / 无 bridge 注册）。
const ENV_DISABLE_TELEMETRY: &str = "DISABLE_TELEMETRY";
const ENV_DISABLE_NONESSENTIAL_TRAFFIC: &str = "CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC";
// 真实会让 Keychain OAuth 切号失效的环境变量。
// 注意：不存在 CLAUDE_CODE_API_KEY_HELPER 这个 env（apiKeyHelper 只在 settings.json 里），
// 这里补上 codex 逆向确认的两个 file-descriptor 变量。
const AUTH_ENV_KEYS: &[&str] = &[
    "ANTHROPIC_API_KEY",
    "ANTHROPIC_AUTH_TOKEN",
    "CLAUDE_CODE_OAUTH_TOKEN",
    "CLAUDE_CODE_OAUTH_TOKEN_FILE_DESCRIPTOR",
    "CLAUDE_CODE_API_KEY_FILE_DESCRIPTOR",
];
const PROFILE_ENV_KEYS: &[&str] = &["TZ", "LANG", "LC_ALL"];

#[derive(Debug, Clone, Serialize, Deserialize)]
struct StoredProfile {
    id: String,
    name: String,
    notes: Option<String>,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
    last_switched_at: Option<DateTime<Utc>>,
    claude_json: Value,
    settings_json: Option<Value>,
    keychain_password: Option<String>,
    meta: ProfileMeta,
    #[serde(default)]
    clash: Option<ProfileClashBinding>,
    #[serde(default)]
    runtime: Option<ProfileRuntimeBinding>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ProfileClashBinding {
    enabled: bool,
    group: String,
    node: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct ProfileRuntimeBinding {
    timezone: Option<String>,
    locale: Option<String>,
    chrome_profile: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct ProfileMeta {
    email: Option<String>,
    account_uuid: Option<String>,
    organization_uuid: Option<String>,
    organization_name: Option<String>,
    user_id_hash: Option<String>,
    has_oauth_account: bool,
    has_keychain_credentials: bool,
    has_trusted_device_token: bool,
    subscription_type: Option<String>,
    rate_limit_tier: Option<String>,
}

/// 遥测去关联模式（三态，前后端契约里序列化成 camelCase 字符串）：
/// - `Default`         → 不注入任何隐私 env（关掉去关联）。
/// - `DisableTelemetry`→ settings.env 注入 DISABLE_TELEMETRY=1（**默认值**，推荐）。
/// - `EssentialOnly`   → settings.env 注入 CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC=1
///   （最强，副作用：手动更新 / 新模型滞后、无 bridge 注册）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
enum TelemetryMode {
    Default,
    DisableTelemetry,
    EssentialOnly,
}

impl TelemetryMode {
    /// 该模式要注入 settings.env 的隐私 env key（`Default` 不注入返回 `None`）。
    fn env_key(self) -> Option<&'static str> {
        match self {
            TelemetryMode::Default => None,
            TelemetryMode::DisableTelemetry => Some(ENV_DISABLE_TELEMETRY),
            TelemetryMode::EssentialOnly => Some(ENV_DISABLE_NONESSENTIAL_TRAFFIC),
        }
    }
}

/// 老 store 缺字段 / 全新安装时的默认遥测模式 = DisableTelemetry（默认开启去关联）。
fn default_telemetry_mode() -> TelemetryMode {
    TelemetryMode::DisableTelemetry
}

fn default_runtime_for_profile(name: &str, node: Option<&str>) -> ProfileRuntimeBinding {
    let haystack = format!(
        "{} {}",
        name.to_lowercase(),
        node.unwrap_or("").to_lowercase()
    );
    if haystack.contains("尼") || haystack.contains("nigeria") || haystack.contains("南非") {
        ProfileRuntimeBinding {
            timezone: Some("Africa/Lagos".to_string()),
            locale: Some("en_US.UTF-8".to_string()),
            chrome_profile: Some("Profile 4".to_string()),
        }
    } else if haystack.contains("美") || haystack.contains("us") || haystack.contains("38") {
        ProfileRuntimeBinding {
            timezone: Some("America/Los_Angeles".to_string()),
            locale: Some("en_US.UTF-8".to_string()),
            chrome_profile: Some("Profile 35".to_string()),
        }
    } else {
        ProfileRuntimeBinding {
            timezone: Some("America/Los_Angeles".to_string()),
            locale: Some("en_US.UTF-8".to_string()),
            chrome_profile: None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Store {
    profiles: Vec<StoredProfile>,
    current_profile_id: Option<String>,
    #[serde(default)]
    pending_new_account: Option<PendingNewAccount>,
    // 缺省 = DisableTelemetry：老 store 没这个字段、新装都默认开启去关联。
    #[serde(default = "default_telemetry_mode")]
    telemetry_mode: TelemetryMode,
}

// 不能用 #[derive(Default)]：那会让 telemetry_mode = TelemetryMode 的派生默认值，
// 而我们要的默认是 DisableTelemetry。手写 Default 保证「全新空 store」也默认开启去关联。
impl Default for Store {
    fn default() -> Self {
        Store {
            profiles: Vec::new(),
            current_profile_id: None,
            pending_new_account: None,
            telemetry_mode: default_telemetry_mode(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct PendingNewAccount {
    id: String,
    name: String,
    notes: Option<String>,
    group: String,
    node: String,
    runtime: ProfileRuntimeBinding,
    created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize)]
struct ProfileSummary {
    id: String,
    name: String,
    notes: Option<String>,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
    last_switched_at: Option<DateTime<Utc>>,
    meta: ProfileMeta,
    clash: Option<ProfileClashBinding>,
    runtime: Option<ProfileRuntimeBinding>,
    is_current: bool,
}

#[derive(Debug, Clone, Serialize)]
struct ClaudeStatus {
    claude_json_exists: bool,
    settings_json_exists: bool,
    credentials_json_exists: bool,
    keychain_exists: bool,
    keychain_parse_ok: bool,
    meta: ProfileMeta,
    claude_json_path: String,
    settings_json_path: String,
    data_dir: String,
    backup_dir: String,
    session_isolation: SessionIsolationStatus,
    profile_count: usize,
    current_profile_id: Option<String>,
    current_profile_name: Option<String>,
    pending_new_account: Option<PendingNewAccount>,
    // 当前遥测去关联模式（"default"/"disableTelemetry"/"essentialOnly"）。
    telemetry_mode: TelemetryMode,
    warnings: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
struct SessionIsolationStatus {
    enabled: bool,
    live_path: String,
    target_path: Option<String>,
    current_profile_path: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
struct BackupResult {
    id: String,
    path: String,
    created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize)]
struct BackupSummary {
    id: String,
    label: String,
    // ISO 字符串（chrono 默认 Serialize 即 RFC3339 ISO 格式）。
    created_at: String,
}

#[derive(Debug, Clone, Serialize)]
struct SwitchResult {
    switched_to: String,
    backup: BackupResult,
    clash: Option<ClashSwitchResult>,
    restart_hint: String,
    // 非阻断告警：例如身份不匹配跳过回写、Claude Code 仍在运行需重启等。
    warnings: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
struct PrepareNewAccountResult {
    pending: PendingNewAccount,
    backup: BackupResult,
    clash: ClashSwitchResult,
    warnings: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
struct RestoreResult {
    restored_from: String,
    backup: BackupResult,
    warnings: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
struct ClashStatus {
    available: bool,
    controller: String,
    group: String,
    group_type: Option<String>,
    now: Option<String>,
    nodes: Vec<String>,
    error: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
struct ClashSwitchResult {
    group: String,
    node: String,
    previous: Option<String>,
    verified: bool,
}

#[derive(Debug, Clone, Default, Serialize)]
struct TokenTotals {
    input_tokens: u64,
    cache_creation_input_tokens: u64,
    cache_read_input_tokens: u64,
    output_tokens: u64,
    total_tokens: u64,
}

impl TokenTotals {
    fn add_usage(&mut self, usage: &Value) {
        let input = number_field(usage, "input_tokens");
        let cache_creation = number_field(usage, "cache_creation_input_tokens");
        let cache_read = number_field(usage, "cache_read_input_tokens");
        let output = number_field(usage, "output_tokens");

        self.input_tokens += input;
        self.cache_creation_input_tokens += cache_creation;
        self.cache_read_input_tokens += cache_read;
        self.output_tokens += output;
        self.total_tokens += input + cache_creation + output;
    }
}

#[derive(Debug, Clone, Serialize)]
struct UsageWindow {
    label: String,
    totals: TokenTotals,
    message_count: u64,
    reset_at: Option<DateTime<Utc>>,
    used_percent: Option<f64>,
}

#[derive(Debug, Clone, Serialize)]
struct DailyUsage {
    date: String,
    totals: TokenTotals,
    message_count: u64,
}

#[derive(Debug, Clone, Serialize)]
struct ClaudeUsageSnapshot {
    updated_at: DateTime<Utc>,
    scanned_files: usize,
    scanned_messages: u64,
    latest_message_at: Option<DateTime<Utc>>,
    session: UsageWindow,
    weekly: UsageWindow,
    today: UsageWindow,
    last_30_days: UsageWindow,
    daily: Vec<DailyUsage>,
    top_model: Option<String>,
    warnings: Vec<String>,
}

#[derive(Debug, Clone)]
struct UsageRecord {
    timestamp: DateTime<Utc>,
    model: String,
    usage: Value,
}

#[derive(Debug, Clone)]
struct CachedOauthUsage {
    fetched_at: DateTime<Utc>,
    value: Value,
}

static OAUTH_USAGE_CACHE: OnceLock<Mutex<Option<CachedOauthUsage>>> = OnceLock::new();
static OAUTH_PROFILE_CACHE: OnceLock<Mutex<Option<CachedOauthUsage>>> = OnceLock::new();

#[derive(Debug, Clone)]
struct ClashRuntimeConfig {
    controller: String,
    secret: Option<String>,
    proxy: Option<String>,
}

fn home_dir() -> Result<PathBuf, String> {
    dirs::home_dir().ok_or_else(|| "无法定位 HOME 目录".to_string())
}

fn claude_dir() -> Result<PathBuf, String> {
    Ok(home_dir()?.join(".claude"))
}

fn claude_json_path() -> Result<PathBuf, String> {
    Ok(home_dir()?.join(".claude.json"))
}

fn claude_settings_path() -> Result<PathBuf, String> {
    Ok(claude_dir()?.join("settings.json"))
}

fn legacy_credentials_path() -> Result<PathBuf, String> {
    Ok(claude_dir()?.join(".credentials.json"))
}

fn app_data_dir() -> Result<PathBuf, String> {
    Ok(home_dir()?.join(".claude-switcher"))
}

fn store_path() -> Result<PathBuf, String> {
    Ok(app_data_dir()?.join("store.private.json"))
}

fn backups_dir() -> Result<PathBuf, String> {
    Ok(app_data_dir()?.join("backups"))
}

fn session_profiles_dir() -> Result<PathBuf, String> {
    Ok(app_data_dir()?.join("session-profiles"))
}

fn session_backups_dir() -> Result<PathBuf, String> {
    Ok(app_data_dir()?.join("session-backups"))
}

fn clash_verge_dir() -> Result<PathBuf, String> {
    Ok(home_dir()?.join("Library/Application Support/io.github.clash-verge-rev.clash-verge-rev"))
}

fn clash_config_candidates() -> Result<Vec<PathBuf>, String> {
    let base = clash_verge_dir()?;
    Ok(vec![
        base.join("config.yaml"),
        base.join("clash-verge.yaml"),
        base.join("clash-verge-check.yaml"),
    ])
}

fn ensure_app_dirs() -> Result<(), String> {
    fs::create_dir_all(app_data_dir()?).map_err(|e| e.to_string())?;
    fs::create_dir_all(backups_dir()?).map_err(|e| e.to_string())?;
    fs::create_dir_all(session_profiles_dir()?).map_err(|e| e.to_string())?;
    fs::create_dir_all(session_backups_dir()?).map_err(|e| e.to_string())?;
    Ok(())
}

#[cfg(unix)]
fn chmod_600(path: &PathBuf) -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt;
    let mut perms = fs::metadata(path).map_err(|e| e.to_string())?.permissions();
    perms.set_mode(0o600);
    fs::set_permissions(path, perms).map_err(|e| e.to_string())
}

#[cfg(not(unix))]
fn chmod_600(_path: &PathBuf) -> Result<(), String> {
    Ok(())
}

fn read_json_optional(path: PathBuf) -> Result<Option<Value>, String> {
    if !path.exists() {
        return Ok(None);
    }
    let raw = fs::read_to_string(path).map_err(|e| e.to_string())?;
    serde_json::from_str(&raw)
        .map(Some)
        .map_err(|e| format!("JSON 解析失败: {e}"))
}

fn read_yaml_optional(path: PathBuf) -> Result<Option<Value>, String> {
    if !path.exists() {
        return Ok(None);
    }
    let raw = fs::read_to_string(path).map_err(|e| e.to_string())?;
    serde_yaml::from_str::<Value>(&raw)
        .map(Some)
        .map_err(|e| format!("YAML 解析失败: {e}"))
}

fn write_json_pretty(path: PathBuf, value: &Value) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    }
    let raw = serde_json::to_string_pretty(value).map_err(|e| e.to_string())?;
    fs::write(&path, format!("{raw}\n")).map_err(|e| e.to_string())?;
    chmod_600(&path)
}

fn load_store() -> Result<Store, String> {
    ensure_app_dirs()?;
    let path = store_path()?;
    if !path.exists() {
        return Ok(Store::default());
    }
    let raw = fs::read_to_string(path).map_err(|e| e.to_string())?;
    let mut store: Store =
        serde_json::from_str(&raw).map_err(|e| format!("store.private.json 解析失败: {e}"))?;

    // C2：解密每个 profile 的 keychain_password。
    // 旧明文（不以 "enc:v1:" 开头）由 decrypt_secret 原样返回；解密失败返回清晰错误。
    for profile in &mut store.profiles {
        if let Some(enc) = profile.keychain_password.take() {
            let plain = decrypt_secret(&enc)
                .map_err(|e| format!("解密账号「{}」的 Keychain 凭据失败: {e}", profile.name))?;
            profile.keychain_password = Some(plain);
        }
        if profile.runtime.is_none() {
            profile.runtime = Some(default_runtime_for_profile(
                &profile.name,
                profile.clash.as_ref().map(|binding| binding.node.as_str()),
            ));
        }
    }
    Ok(store)
}

fn save_store(store: &Store) -> Result<(), String> {
    ensure_app_dirs()?;
    let path = store_path()?;

    // C2：落盘前把每个 profile 的明文 keychain_password 加密成 "enc:v1:..."。
    // 在 store 的 clone 上加密，不污染内存里调用方持有的明文，方便后续逻辑继续用。
    // 升级后首次 save_store 会把已有明文 store 一并迁移成加密。
    let mut to_persist = store.clone();
    for profile in &mut to_persist.profiles {
        if let Some(plain) = profile.keychain_password.take() {
            let enc = encrypt_keychain_field(&plain)
                .map_err(|e| format!("加密账号「{}」的 Keychain 凭据失败: {e}", profile.name))?;
            profile.keychain_password = Some(enc);
        }
    }

    let raw = serde_json::to_string_pretty(&to_persist).map_err(|e| e.to_string())?;
    fs::write(&path, format!("{raw}\n")).map_err(|e| e.to_string())?;
    chmod_600(&path)
}

fn hash_short(input: &str) -> String {
    let digest = Sha256::digest(input.as_bytes());
    format!("{:x}", digest)[..12].to_string()
}

fn string_field<'a>(value: &'a Value, path: &[&str]) -> Option<&'a str> {
    let mut cur = value;
    for key in path {
        cur = cur.get(*key)?;
    }
    cur.as_str()
}

fn numeric_field(value: &Value, path: &[&str]) -> Option<u64> {
    let mut cur = value;
    for key in path {
        cur = cur.get(*key)?;
    }
    cur.as_u64()
}

fn number_field(value: &Value, key: &str) -> u64 {
    value.get(key).and_then(|v| v.as_u64()).unwrap_or(0)
}

fn claude_projects_dir() -> Result<PathBuf, String> {
    Ok(claude_dir()?.join("projects"))
}

fn profile_sessions_dir(profile_id: &str) -> Result<PathBuf, String> {
    Ok(session_profiles_dir()?.join(profile_id).join("projects"))
}

fn claude_local_dir(name: &str) -> Result<PathBuf, String> {
    Ok(claude_dir()?.join(name))
}

fn profile_claude_local_dir(profile_id: &str, name: &str) -> Result<PathBuf, String> {
    Ok(session_profiles_dir()?.join(profile_id).join(name))
}

fn claude_config_json_path() -> Result<PathBuf, String> {
    Ok(claude_dir()?.join("config.json"))
}

fn profile_claude_config_json_path(profile_id: &str) -> Result<PathBuf, String> {
    Ok(session_profiles_dir()?.join(profile_id).join("config.json"))
}

fn path_is_symlink(path: &Path) -> bool {
    fs::symlink_metadata(path)
        .map(|metadata| metadata.file_type().is_symlink())
        .unwrap_or(false)
}

fn path_exists_or_symlink(path: &Path) -> bool {
    path.exists() || path_is_symlink(path)
}

fn backup_label(label: &str) -> String {
    label
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || ch == '-' || ch == '_' {
                ch
            } else {
                '-'
            }
        })
        .collect()
}

fn move_path_to_session_backup(path: &Path, label: &str) -> Result<PathBuf, String> {
    fs::create_dir_all(session_backups_dir()?).map_err(|e| e.to_string())?;
    let backup_name = format!(
        "{}-{}-{}",
        Utc::now().format("%Y%m%d%H%M%S"),
        backup_label(label),
        Uuid::new_v4()
    );
    let backup_path = session_backups_dir()?.join(backup_name);
    fs::rename(path, &backup_path).map_err(|e| format!("移动 session 目录到备份失败: {e}"))?;
    Ok(backup_path)
}

#[cfg(unix)]
fn link_path(target: &Path, live: &Path, label: &str) -> Result<(), String> {
    use std::os::unix::fs::symlink;
    symlink(target, live).map_err(|e| format!("创建 {label} 隔离链接失败: {e}"))
}

#[cfg(not(unix))]
fn link_path(_target: &Path, _live: &Path, label: &str) -> Result<(), String> {
    Err(format!("当前平台暂不支持 Claude {label} 符号链接隔离"))
}

fn adopt_live_sessions_for_profile(profile_id: &str) -> Result<Vec<String>, String> {
    ensure_app_dirs()?;
    let live = claude_projects_dir()?;
    let target = profile_sessions_dir(profile_id)?;
    if let Some(parent) = target.parent() {
        fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    }

    if !path_exists_or_symlink(&live) {
        fs::create_dir_all(&target).map_err(|e| format!("创建 profile session 目录失败: {e}"))?;
        return Ok(Vec::new());
    }

    if path_is_symlink(&live) {
        let linked_to = fs::read_link(&live).map_err(|e| format!("读取 session 链接失败: {e}"))?;
        if linked_to == target {
            fs::create_dir_all(&target)
                .map_err(|e| format!("创建 profile session 目录失败: {e}"))?;
            return Ok(Vec::new());
        }
        fs::create_dir_all(&target).map_err(|e| format!("创建 profile session 目录失败: {e}"))?;
        return Ok(vec![format!(
            "当前 ~/.claude/projects 已指向其他隔离目录（{}），未把它接管到当前账号",
            linked_to.to_string_lossy()
        )]);
    }

    let mut warnings = Vec::new();
    if path_exists_or_symlink(&target) {
        let backup_path = move_path_to_session_backup(&target, "existing-profile-projects")?;
        warnings.push(format!(
            "已备份目标账号原 session 目录：{}",
            backup_path.to_string_lossy()
        ));
    }
    fs::rename(&live, &target).map_err(|e| {
        format!(
            "接管当前 ~/.claude/projects 到账号隔离目录失败（{} -> {}）: {e}",
            live.to_string_lossy(),
            target.to_string_lossy()
        )
    })?;
    warnings.push(format!(
        "已把当前 Claude sessions 接管到账号隔离目录：{}",
        target.to_string_lossy()
    ));
    Ok(warnings)
}

fn activate_profile_sessions(profile_id: &str) -> Result<Vec<String>, String> {
    ensure_app_dirs()?;
    let live = claude_projects_dir()?;
    let target = profile_sessions_dir(profile_id)?;
    fs::create_dir_all(&target).map_err(|e| format!("创建 profile session 目录失败: {e}"))?;
    if let Some(parent) = live.parent() {
        fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    }

    let mut warnings = Vec::new();
    if path_is_symlink(&live) {
        let linked_to = fs::read_link(&live).map_err(|e| format!("读取 session 链接失败: {e}"))?;
        if linked_to == target {
            return Ok(warnings);
        }
        fs::remove_file(&live).map_err(|e| format!("移除旧 session 链接失败: {e}"))?;
    } else if live.exists() {
        let backup_path = move_path_to_session_backup(&live, "unowned-live-projects")?;
        warnings.push(format!(
            "发现未归属的 ~/.claude/projects，已先备份：{}",
            backup_path.to_string_lossy()
        ));
    }

    link_path(&target, &live, "session")?;
    warnings.push(format!(
        "已启用账号 session 隔离：~/.claude/projects -> {}",
        target.to_string_lossy()
    ));
    Ok(warnings)
}

fn session_isolation_status(
    current_profile_id: Option<&str>,
) -> Result<SessionIsolationStatus, String> {
    let live = claude_projects_dir()?;
    let current_profile_path = current_profile_id
        .map(profile_sessions_dir)
        .transpose()?
        .map(|path| path.to_string_lossy().to_string());
    let target_path = if path_is_symlink(&live) {
        fs::read_link(&live)
            .ok()
            .map(|path| path.to_string_lossy().to_string())
    } else {
        None
    };
    let enabled = match (&target_path, &current_profile_path) {
        (Some(target), Some(current)) => target == current,
        _ => false,
    };
    Ok(SessionIsolationStatus {
        enabled,
        live_path: live.to_string_lossy().to_string(),
        target_path,
        current_profile_path,
    })
}

fn adopt_live_claude_dir_for_profile(profile_id: &str, name: &str) -> Result<Vec<String>, String> {
    ensure_app_dirs()?;
    let live = claude_local_dir(name)?;
    let target = profile_claude_local_dir(profile_id, name)?;
    if let Some(parent) = target.parent() {
        fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    }

    if !path_exists_or_symlink(&live) {
        fs::create_dir_all(&target).map_err(|e| format!("创建 profile {name} 目录失败: {e}"))?;
        return Ok(Vec::new());
    }

    if path_is_symlink(&live) {
        let linked_to = fs::read_link(&live).map_err(|e| format!("读取 {name} 链接失败: {e}"))?;
        if linked_to == target {
            fs::create_dir_all(&target)
                .map_err(|e| format!("创建 profile {name} 目录失败: {e}"))?;
            return Ok(Vec::new());
        }
        fs::create_dir_all(&target).map_err(|e| format!("创建 profile {name} 目录失败: {e}"))?;
        return Ok(vec![format!(
            "当前 ~/.claude/{name} 已指向其他隔离目录（{}），未把它接管到当前账号",
            linked_to.to_string_lossy()
        )]);
    }

    let mut warnings = Vec::new();
    if path_exists_or_symlink(&target) {
        let backup_path =
            move_path_to_session_backup(&target, &format!("existing-profile-{name}"))?;
        warnings.push(format!(
            "已备份目标账号原 {name} 目录：{}",
            backup_path.to_string_lossy()
        ));
    }
    fs::rename(&live, &target).map_err(|e| {
        format!(
            "接管当前 ~/.claude/{name} 到账号隔离目录失败（{} -> {}）: {e}",
            live.to_string_lossy(),
            target.to_string_lossy()
        )
    })?;
    warnings.push(format!(
        "已把当前 Claude {name} 接管到账号隔离目录：{}",
        target.to_string_lossy()
    ));
    Ok(warnings)
}

fn activate_profile_claude_dir(profile_id: &str, name: &str) -> Result<Vec<String>, String> {
    ensure_app_dirs()?;
    let live = claude_local_dir(name)?;
    let target = profile_claude_local_dir(profile_id, name)?;
    fs::create_dir_all(&target).map_err(|e| format!("创建 profile {name} 目录失败: {e}"))?;
    if let Some(parent) = live.parent() {
        fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    }

    let mut warnings = Vec::new();
    if path_is_symlink(&live) {
        let linked_to = fs::read_link(&live).map_err(|e| format!("读取 {name} 链接失败: {e}"))?;
        if linked_to == target {
            return Ok(warnings);
        }
        fs::remove_file(&live).map_err(|e| format!("移除旧 {name} 链接失败: {e}"))?;
    } else if live.exists() {
        let backup_path = move_path_to_session_backup(&live, &format!("unowned-live-{name}"))?;
        warnings.push(format!(
            "发现未归属的 ~/.claude/{name}，已先备份：{}",
            backup_path.to_string_lossy()
        ));
    }

    link_path(&target, &live, name)?;
    warnings.push(format!(
        "已启用账号 {name} 隔离：~/.claude/{name} -> {}",
        target.to_string_lossy()
    ));
    Ok(warnings)
}

fn adopt_live_claude_config_for_profile(profile_id: &str) -> Result<Vec<String>, String> {
    ensure_app_dirs()?;
    let live = claude_config_json_path()?;
    let target = profile_claude_config_json_path(profile_id)?;
    if let Some(parent) = target.parent() {
        fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    }

    if !path_exists_or_symlink(&live) {
        write_json_pretty(target, &json!({}))?;
        return Ok(Vec::new());
    }

    if path_is_symlink(&live) {
        let linked_to =
            fs::read_link(&live).map_err(|e| format!("读取 config.json 链接失败: {e}"))?;
        if linked_to == target {
            if !target.exists() {
                write_json_pretty(target, &json!({}))?;
            }
            return Ok(Vec::new());
        }
        if !target.exists() {
            write_json_pretty(target, &json!({}))?;
        }
        return Ok(vec![format!(
            "当前 ~/.claude/config.json 已指向其他隔离文件（{}），未把它接管到当前账号",
            linked_to.to_string_lossy()
        )]);
    }

    let mut warnings = Vec::new();
    if path_exists_or_symlink(&target) {
        let backup_path = move_path_to_session_backup(&target, "existing-profile-config-json")?;
        warnings.push(format!(
            "已备份目标账号原 config.json：{}",
            backup_path.to_string_lossy()
        ));
    }
    fs::rename(&live, &target).map_err(|e| {
        format!(
            "接管当前 ~/.claude/config.json 到账号隔离文件失败（{} -> {}）: {e}",
            live.to_string_lossy(),
            target.to_string_lossy()
        )
    })?;
    warnings.push(format!(
        "已把当前 Claude config.json 接管到账号隔离文件：{}",
        target.to_string_lossy()
    ));
    Ok(warnings)
}

fn activate_profile_claude_config(profile_id: &str) -> Result<Vec<String>, String> {
    ensure_app_dirs()?;
    let live = claude_config_json_path()?;
    let target = profile_claude_config_json_path(profile_id)?;
    if let Some(parent) = target.parent() {
        fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    }
    if !target.exists() {
        write_json_pretty(target.clone(), &json!({}))?;
    }
    if let Some(parent) = live.parent() {
        fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    }

    let mut warnings = Vec::new();
    if path_is_symlink(&live) {
        let linked_to =
            fs::read_link(&live).map_err(|e| format!("读取 config.json 链接失败: {e}"))?;
        if linked_to == target {
            return Ok(warnings);
        }
        fs::remove_file(&live).map_err(|e| format!("移除旧 config.json 链接失败: {e}"))?;
    } else if live.exists() {
        let backup_path = move_path_to_session_backup(&live, "unowned-live-config-json")?;
        warnings.push(format!(
            "发现未归属的 ~/.claude/config.json，已先备份：{}",
            backup_path.to_string_lossy()
        ));
    }

    link_path(&target, &live, "config.json")?;
    warnings.push(format!(
        "已启用账号 config.json 隔离：~/.claude/config.json -> {}",
        target.to_string_lossy()
    ));
    Ok(warnings)
}

fn adopt_live_claude_local_state_for_profile(profile_id: &str) -> Result<Vec<String>, String> {
    let mut warnings = Vec::new();
    warnings.extend(adopt_live_sessions_for_profile(profile_id)?);
    warnings.extend(adopt_live_claude_dir_for_profile(profile_id, "telemetry")?);
    warnings.extend(adopt_live_claude_dir_for_profile(
        profile_id,
        "file-history",
    )?);
    warnings.extend(adopt_live_claude_dir_for_profile(
        profile_id,
        "shell-snapshots",
    )?);
    warnings.extend(adopt_live_claude_dir_for_profile(profile_id, "cache")?);
    warnings.extend(adopt_live_claude_dir_for_profile(profile_id, "debug")?);
    warnings.extend(adopt_live_claude_dir_for_profile(
        profile_id,
        "plugins/data",
    )?);
    warnings.extend(adopt_live_claude_config_for_profile(profile_id)?);
    Ok(warnings)
}

fn activate_profile_claude_local_state(profile_id: &str) -> Result<Vec<String>, String> {
    let mut warnings = Vec::new();
    warnings.extend(activate_profile_sessions(profile_id)?);
    warnings.extend(activate_profile_claude_dir(profile_id, "telemetry")?);
    warnings.extend(activate_profile_claude_dir(profile_id, "file-history")?);
    warnings.extend(activate_profile_claude_dir(profile_id, "shell-snapshots")?);
    warnings.extend(activate_profile_claude_dir(profile_id, "cache")?);
    warnings.extend(activate_profile_claude_dir(profile_id, "debug")?);
    warnings.extend(activate_profile_claude_dir(profile_id, "plugins/data")?);
    warnings.extend(activate_profile_claude_config(profile_id)?);
    Ok(warnings)
}

fn collect_jsonl_files(dir: &PathBuf, files: &mut Vec<PathBuf>) -> Result<(), String> {
    if !dir.exists() {
        return Ok(());
    }
    let entries = fs::read_dir(dir).map_err(|e| format!("读取 Claude 日志目录失败: {e}"))?;
    for entry in entries {
        let entry = entry.map_err(|e| e.to_string())?;
        let path = entry.path();
        if path.is_dir() {
            collect_jsonl_files(&path, files)?;
        } else if path.extension().and_then(|ext| ext.to_str()) == Some("jsonl") {
            files.push(path);
        }
    }
    Ok(())
}

fn should_scan_usage_file(path: &PathBuf, cutoff: DateTime<Utc>) -> bool {
    let path_text = path.to_string_lossy();
    if path_text.contains("/subagents/") || path_text.contains("CodexBar-ClaudeProbe") {
        return false;
    }
    let Ok(metadata) = fs::metadata(path) else {
        return false;
    };
    let Ok(modified) = metadata.modified() else {
        return true;
    };
    let modified: DateTime<Utc> = modified.into();
    modified >= cutoff
}

fn usage_window(
    label: &str,
    totals: TokenTotals,
    message_count: u64,
    reset_at: Option<DateTime<Utc>>,
) -> UsageWindow {
    UsageWindow {
        label: label.to_string(),
        totals,
        message_count,
        reset_at,
        used_percent: None,
    }
}

fn parse_oauth_reset(value: Option<&str>) -> Option<DateTime<Utc>> {
    let raw = value?.trim();
    if raw.is_empty() {
        return None;
    }
    DateTime::parse_from_rfc3339(raw)
        .map(|value| value.with_timezone(&Utc))
        .ok()
}

fn apply_oauth_window(window: &mut UsageWindow, value: Option<&Value>) -> bool {
    let Some(value) = value else {
        return false;
    };
    let Some(utilization) = value.get("utilization").and_then(|v| v.as_f64()) else {
        return false;
    };
    window.used_percent = Some(utilization.clamp(0.0, 100.0));
    window.reset_at = parse_oauth_reset(value.get("resets_at").and_then(|v| v.as_str()));
    true
}

fn curl_config_quote(value: &str) -> String {
    value
        .replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace(['\n', '\r'], "")
}

fn oauth_access_token_from_raw(raw: &str) -> Result<String, String> {
    let parsed: Value =
        serde_json::from_str(raw).map_err(|e| format!("Keychain OAuth JSON 解析失败: {e}"))?;
    let oauth = parsed.get("claudeAiOauth").unwrap_or(&parsed);
    string_field(oauth, &["accessToken"])
        .or_else(|| string_field(oauth, &["access_token"]))
        .map(ToOwned::to_owned)
        .ok_or_else(|| "Keychain OAuth 中没有 accessToken".to_string())
}

fn claude_oauth_api(path: &str, access_token: &str, max_time_secs: u64) -> Result<Value, String> {
    let runtime = detect_clash_runtime_config();
    let proxy = runtime
        .proxy
        .map(|value| format!("proxy = \"{}\"\n", curl_config_quote(&value)))
        .unwrap_or_default();
    let config = format!(
        concat!(
            "url = \"https://api.anthropic.com{}\"\n",
            "{}",
            "connect-timeout = 3\n",
            "header = \"Authorization: Bearer {}\"\n",
            "header = \"Accept: application/json\"\n",
            "header = \"Content-Type: application/json\"\n",
            "header = \"anthropic-beta: oauth-2025-04-20\"\n",
            "header = \"User-Agent: claude-code/2.1.0\"\n"
        ),
        curl_config_quote(path),
        proxy,
        curl_config_quote(access_token)
    );
    let mut child = Command::new("curl")
        .arg("-sS")
        .arg("--max-time")
        .arg(max_time_secs.to_string())
        .arg("--retry")
        .arg("0")
        .arg("--config")
        .arg("-")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("调用 Claude OAuth API 失败: {e}"))?;
    {
        let stdin = child
            .stdin
            .as_mut()
            .ok_or_else(|| "无法写入 Claude OAuth API 请求配置".to_string())?;
        stdin
            .write_all(config.as_bytes())
            .map_err(|e| format!("写入 Claude OAuth API 请求配置失败: {e}"))?;
    }
    let output = child
        .wait_with_output()
        .map_err(|e| format!("等待 Claude OAuth API 失败: {e}"))?;
    if !output.status.success() {
        return Err(format!(
            "Claude OAuth API HTTP 失败: {}",
            String::from_utf8_lossy(&output.stderr)
        ));
    }
    let body = String::from_utf8_lossy(&output.stdout);
    serde_json::from_str(&body).map_err(|e| format!("Claude OAuth API JSON 解析失败: {e}"))
}

fn cached_oauth_usage(access_token: &str) -> Result<Value, String> {
    cached_oauth_endpoint(
        OAUTH_USAGE_CACHE.get_or_init(|| Mutex::new(None)),
        "/api/oauth/usage",
        access_token,
        Duration::minutes(10),
    )
}

fn cached_oauth_profile(access_token: &str) -> Result<Value, String> {
    cached_oauth_endpoint(
        OAUTH_PROFILE_CACHE.get_or_init(|| Mutex::new(None)),
        "/api/oauth/profile",
        access_token,
        Duration::hours(6),
    )
}

fn cached_oauth_endpoint(
    cache: &Mutex<Option<CachedOauthUsage>>,
    path: &str,
    access_token: &str,
    ttl: Duration,
) -> Result<Value, String> {
    match claude_oauth_api(path, access_token, 6) {
        Ok(value) => {
            if let Ok(mut guard) = cache.lock() {
                *guard = Some(CachedOauthUsage {
                    fetched_at: Utc::now(),
                    value: value.clone(),
                });
            }
            Ok(value)
        }
        Err(error) => {
            let cached = cache
                .lock()
                .ok()
                .and_then(|guard| guard.clone())
                .filter(|cached| Utc::now() - cached.fetched_at < ttl)
                .map(|cached| cached.value);
            cached.ok_or(error)
        }
    }
}

fn apply_oauth_usage(snapshot: &mut ClaudeUsageSnapshot) -> Result<(), String> {
    let Some(raw) = read_keychain_password()? else {
        return Err("Keychain 中没有 Claude OAuth 凭据".to_string());
    };
    let access_token = oauth_access_token_from_raw(&raw)?;
    let value = cached_oauth_usage(&access_token)?;

    let session_ok = apply_oauth_window(&mut snapshot.session, value.get("five_hour"));
    let weekly_ok = apply_oauth_window(&mut snapshot.weekly, value.get("seven_day"));
    if !session_ok && !weekly_ok {
        return Err("Claude OAuth usage 响应缺少 five_hour/seven_day utilization".to_string());
    }
    Ok(())
}

fn add_daily_usage(
    daily: &mut BTreeMap<String, (TokenTotals, u64)>,
    timestamp: DateTime<Utc>,
    usage: &Value,
) {
    let key = timestamp.date_naive().to_string();
    let (totals, count) = daily.entry(key).or_default();
    totals.add_usage(usage);
    *count += 1;
}

fn estimate_reset_at(earliest: Option<DateTime<Utc>>, window: Duration) -> Option<DateTime<Utc>> {
    earliest.map(|value| value + window)
}

fn update_earliest(target: &mut Option<DateTime<Utc>>, timestamp: DateTime<Utc>) {
    if target.map(|current| timestamp < current).unwrap_or(true) {
        *target = Some(timestamp);
    }
}

fn update_latest(target: &mut Option<DateTime<Utc>>, timestamp: DateTime<Utc>) {
    if target.map(|current| timestamp > current).unwrap_or(true) {
        *target = Some(timestamp);
    }
}

fn model_from_message(message: &Value) -> Option<String> {
    let model = string_field(message, &["model"])?;
    let clean = model.trim();
    if clean.is_empty() || clean == "<synthetic>" {
        None
    } else {
        Some(clean.to_string())
    }
}

fn usage_dedupe_key(path: &Path, value: &Value, message: &Value, fallback: u64) -> String {
    let message_id = string_field(message, &["id"])
        .or_else(|| string_field(value, &["messageId"]))
        .or_else(|| string_field(value, &["message_id"]))
        .or_else(|| string_field(value, &["uuid"]));
    let request_id = string_field(value, &["requestId"])
        .or_else(|| string_field(value, &["request_id"]))
        .or_else(|| string_field(message, &["requestId"]))
        .or_else(|| string_field(message, &["request_id"]));
    match (message_id, request_id) {
        (Some(message_id), Some(request_id)) => format!("{message_id}:{request_id}"),
        (Some(message_id), None) => message_id.to_string(),
        (None, Some(request_id)) => request_id.to_string(),
        (None, None) => format!("{}:{fallback}", path.to_string_lossy()),
    }
}

fn usage_total_for_dedupe(usage: &Value) -> u64 {
    number_field(usage, "input_tokens")
        + number_field(usage, "cache_creation_input_tokens")
        + number_field(usage, "cache_read_input_tokens")
        + number_field(usage, "output_tokens")
}

fn claude_usage_snapshot() -> Result<ClaudeUsageSnapshot, String> {
    let now = Utc::now();
    let session_window = Duration::hours(5);
    let weekly_window = Duration::days(7);
    let month_window = Duration::days(30);
    let session_cutoff = now - session_window;
    let weekly_cutoff = now - weekly_window;
    let month_cutoff = now - month_window;
    let today = now.date_naive();

    let mut files = Vec::new();
    collect_jsonl_files(&claude_projects_dir()?, &mut files)?;
    files.retain(|path| should_scan_usage_file(path, month_cutoff));

    let mut scanned_messages = 0;
    let mut fallback_usage_key = 0u64;
    let mut usage_records: BTreeMap<String, UsageRecord> = BTreeMap::new();
    let mut warnings = Vec::new();

    for path in &files {
        let file = match fs::File::open(path) {
            Ok(file) => file,
            Err(e) => {
                warnings.push(format!("跳过无法读取的日志文件: {e}"));
                continue;
            }
        };
        for line in BufReader::new(file).lines() {
            let Ok(line) = line else {
                continue;
            };
            if line.trim().is_empty() {
                continue;
            }
            let Ok(value) = serde_json::from_str::<Value>(&line) else {
                continue;
            };
            let Some(timestamp_raw) = string_field(&value, &["timestamp"]) else {
                continue;
            };
            let Ok(timestamp) = DateTime::parse_from_rfc3339(timestamp_raw) else {
                continue;
            };
            let timestamp = timestamp.with_timezone(&Utc);
            if timestamp < month_cutoff {
                continue;
            }

            let message = value.get("message").unwrap_or(&value);
            let entry_type = string_field(&value, &["type"])
                .or_else(|| string_field(message, &["type"]))
                .unwrap_or("");
            if entry_type != "assistant" {
                continue;
            }
            if value
                .get("isSidechain")
                .and_then(|item| item.as_bool())
                .unwrap_or(false)
            {
                continue;
            }
            let Some(model) = model_from_message(message) else {
                continue;
            };
            let Some(usage) = message.get("usage").or_else(|| value.get("usage")) else {
                continue;
            };
            if !usage.is_object() {
                continue;
            }

            scanned_messages += 1;
            fallback_usage_key += 1;
            let key = usage_dedupe_key(path, &value, message, fallback_usage_key);
            let should_replace = usage_records
                .get(&key)
                .map(|current| {
                    timestamp >= current.timestamp
                        || usage_total_for_dedupe(usage) > usage_total_for_dedupe(&current.usage)
                })
                .unwrap_or(true);
            if should_replace {
                usage_records.insert(
                    key,
                    UsageRecord {
                        timestamp,
                        model,
                        usage: usage.clone(),
                    },
                );
            }
        }
    }

    let mut session_totals = TokenTotals::default();
    let mut weekly_totals = TokenTotals::default();
    let mut today_totals = TokenTotals::default();
    let mut month_totals = TokenTotals::default();
    let mut session_messages = 0;
    let mut weekly_messages = 0;
    let mut today_messages = 0;
    let mut month_messages = 0;
    let mut latest_message_at: Option<DateTime<Utc>> = None;
    let mut latest_session: Option<DateTime<Utc>> = None;
    let mut latest_weekly: Option<DateTime<Utc>> = None;
    let mut earliest_today: Option<DateTime<Utc>> = None;
    let mut earliest_month: Option<DateTime<Utc>> = None;
    let mut daily: BTreeMap<String, (TokenTotals, u64)> = BTreeMap::new();
    let mut model_counts: BTreeMap<String, u64> = BTreeMap::new();

    for record in usage_records.values() {
        let timestamp = record.timestamp;
        let usage = &record.usage;
        if latest_message_at
            .map(|current| timestamp > current)
            .unwrap_or(true)
        {
            latest_message_at = Some(timestamp);
        }
        *model_counts.entry(record.model.clone()).or_default() += 1;

        month_totals.add_usage(usage);
        month_messages += 1;
        update_earliest(&mut earliest_month, timestamp);
        add_daily_usage(&mut daily, timestamp, usage);

        if timestamp >= weekly_cutoff {
            weekly_totals.add_usage(usage);
            weekly_messages += 1;
            update_latest(&mut latest_weekly, timestamp);
        }
        if timestamp >= session_cutoff {
            session_totals.add_usage(usage);
            session_messages += 1;
            update_latest(&mut latest_session, timestamp);
        }
        if timestamp.date_naive() == today {
            today_totals.add_usage(usage);
            today_messages += 1;
            update_earliest(&mut earliest_today, timestamp);
        }
    }

    let seen_days: BTreeSet<String> = daily.keys().cloned().collect();
    let mut daily_rows = Vec::new();
    for offset in (0..30).rev() {
        let date = (today - Duration::days(offset)).to_string();
        let (totals, message_count) = daily.remove(&date).unwrap_or_default();
        daily_rows.push(DailyUsage {
            date,
            totals,
            message_count,
        });
    }
    if seen_days.is_empty() {
        warnings.push("没有从 ~/.claude/projects 读取到最近 30 天的 usage 记录".to_string());
    }

    let top_model = model_counts
        .into_iter()
        .max_by_key(|(_, count)| *count)
        .map(|(model, _)| model);

    let mut snapshot = ClaudeUsageSnapshot {
        updated_at: now,
        scanned_files: files.len(),
        scanned_messages,
        latest_message_at,
        session: usage_window(
            "近 5 小时",
            session_totals,
            session_messages,
            estimate_reset_at(latest_session, session_window),
        ),
        weekly: usage_window(
            "近 7 天",
            weekly_totals,
            weekly_messages,
            estimate_reset_at(latest_weekly, weekly_window),
        ),
        today: usage_window(
            "今天",
            today_totals,
            today_messages,
            estimate_reset_at(earliest_today, Duration::days(1)),
        ),
        last_30_days: usage_window(
            "近 30 天",
            month_totals,
            month_messages,
            estimate_reset_at(earliest_month, month_window),
        ),
        daily: daily_rows,
        top_model,
        warnings,
    };
    if let Err(error) = apply_oauth_usage(&mut snapshot) {
        snapshot.warnings.push(format!(
            "官方 Claude OAuth usage 读取失败，已回退本地日志估算: {error}"
        ));
    }
    Ok(snapshot)
}

fn compact_token_count(value: u64) -> String {
    if value >= 1_000_000_000 {
        let scaled = value as f64 / 1_000_000_000.0;
        if value >= 10_000_000_000 {
            format!("{scaled:.0}B")
        } else {
            format!("{scaled:.1}B")
        }
    } else if value >= 1_000_000 {
        let scaled = value as f64 / 1_000_000.0;
        if value >= 10_000_000 {
            format!("{scaled:.0}M")
        } else {
            format!("{scaled:.1}M")
        }
    } else if value >= 1_000 {
        let scaled = value as f64 / 1_000.0;
        if value >= 10_000 {
            format!("{scaled:.0}K")
        } else {
            format!("{scaled:.1}K")
        }
    } else {
        value.to_string()
    }
}

fn refresh_tray_status(app: &tauri::AppHandle) -> Result<(), String> {
    let Some(tray) = app.tray_by_id("main") else {
        return Ok(());
    };
    let usage = claude_usage_snapshot()?;
    let session = compact_token_count(usage.session.totals.total_tokens);
    let weekly = compact_token_count(usage.weekly.totals.total_tokens);
    let model = usage.top_model.as_deref().unwrap_or("暂无");
    let latest = usage
        .latest_message_at
        .map(|value| value.format("%m-%d %H:%M").to_string())
        .unwrap_or_else(|| "无记录".to_string());
    let tooltip = format!(
        "Claude Switcher\n近 5 小时: {session} token\n近 7 天: {weekly} token\n常用模型: {model}\n最近记录: {latest}"
    );
    tray.set_title(Some(String::new()))
        .map_err(|e| format!("更新菜单栏标题失败: {e}"))?;
    tray.set_tooltip(Some(tooltip))
        .map_err(|e| format!("更新菜单栏提示失败: {e}"))?;
    Ok(())
}

fn position_tray_popup(
    window: &WebviewWindow,
    tray_position: PhysicalPosition<f64>,
) -> Result<(), String> {
    let popup_width = 360.0;
    let scale = window.scale_factor().unwrap_or(1.0);
    let x = (tray_position.x - popup_width * scale / 2.0).max(0.0) as i32;
    let y = (tray_position.y + 4.0) as i32;
    window
        .set_position(Position::Physical(PhysicalPosition::new(x, y)))
        .map_err(|e| format!("定位菜单栏弹窗失败: {e}"))
}

fn toggle_tray_popup(app: &AppHandle, tray_position: PhysicalPosition<f64>) {
    let label = "tray-popup";
    if let Some(window) = app.get_webview_window(label) {
        let is_tray_popup = window
            .url()
            .map(|url| url.as_str().contains("window=tray-popup"))
            .unwrap_or(false);
        if !is_tray_popup {
            let _ = window.close();
        } else {
            if window.is_visible().unwrap_or(false) {
                let _ = window.hide();
                return;
            }
            let _ = position_tray_popup(&window, tray_position);
            let _ = window.show();
            let _ = window.set_focus();
            return;
        }
    }

    match WebviewWindowBuilder::new(
        app,
        label,
        WebviewUrl::App("index.html?window=tray-popup".into()),
    )
    .title("Claude Switcher Status")
    .inner_size(360.0, 410.0)
    .resizable(false)
    .decorations(false)
    .transparent(true)
    .shadow(true)
    .always_on_top(true)
    .skip_taskbar(true)
    .visible(false)
    .build()
    {
        Ok(window) => {
            let window_clone = window.clone();
            window.on_window_event(move |event| {
                if let tauri::WindowEvent::Focused(false) = event {
                    let _ = window_clone.hide();
                }
            });
            let _ = position_tray_popup(&window, tray_position);
            let _ = window.show();
            let _ = window.set_focus();
        }
        Err(error) => eprintln!("[claude-switcher] 创建菜单栏弹窗失败: {error}"),
    }
}

fn show_main_window(app: &AppHandle) {
    if let Some(window) = app.get_webview_window("main") {
        let _ = window.show();
        let _ = window.unminimize();
        let _ = window.set_focus();
    }
    if let Some(popup) = app.get_webview_window("tray-popup") {
        let _ = popup.hide();
    }
}

fn install_tray_handlers(app: &mut tauri::App) -> Result<(), String> {
    let app_handle = app.handle().clone();
    if let Some(tray) = app_handle.tray_by_id("main") {
        let _ = tray.set_title(Some(String::new()));
        let _ = tray.set_tooltip(Some("Claude Switcher".to_string()));
    }

    let refresh_handle = app_handle.clone();
    thread::spawn(move || {
        let _ = refresh_tray_status(&refresh_handle);
        loop {
            thread::sleep(StdDuration::from_secs(60));
            let _ = refresh_tray_status(&refresh_handle);
        }
    });

    app.on_tray_icon_event(|app, event| {
        if let TrayIconEvent::Click {
            button: MouseButton::Left,
            button_state: MouseButtonState::Up,
            position,
            ..
        } = event
        {
            toggle_tray_popup(app, position);
        }
    });

    Ok(())
}

fn extract_meta(claude_json: Option<&Value>, keychain_password: Option<&str>) -> ProfileMeta {
    let mut meta = ProfileMeta::default();

    if let Some(cfg) = claude_json {
        meta.email = string_field(cfg, &["oauthAccount", "email"]).map(ToOwned::to_owned);
        meta.account_uuid =
            string_field(cfg, &["oauthAccount", "accountUuid"]).map(ToOwned::to_owned);
        meta.organization_uuid =
            string_field(cfg, &["oauthAccount", "organizationUuid"]).map(ToOwned::to_owned);
        meta.organization_name =
            string_field(cfg, &["oauthAccount", "organizationName"]).map(ToOwned::to_owned);
        meta.has_oauth_account = cfg.get("oauthAccount").is_some();
        meta.user_id_hash = string_field(cfg, &["userID"]).map(hash_short);
    }

    if let Some(raw) = keychain_password {
        meta.has_keychain_credentials = true;
        if let Ok(parsed) = serde_json::from_str::<Value>(raw) {
            let oauth = parsed.get("claudeAiOauth").unwrap_or(&parsed);
            meta.has_oauth_account = true;
            if meta.email.is_none() {
                meta.email = string_field(oauth, &["email", "accountEmail", "username"])
                    .map(ToOwned::to_owned);
            }
            meta.has_trusted_device_token = oauth.get("trustedDeviceToken").is_some();
            meta.subscription_type =
                string_field(oauth, &["subscriptionType"]).map(ToOwned::to_owned);
            meta.rate_limit_tier = string_field(oauth, &["rateLimitTier"]).map(ToOwned::to_owned);
        }
    }

    meta
}

fn fill_meta_from_saved_profile(meta: &mut ProfileMeta, store: &Store) {
    let Some(current_id) = store.current_profile_id.as_deref() else {
        return;
    };
    let Some(profile) = store.profiles.iter().find(|item| item.id == current_id) else {
        return;
    };
    if meta.email.is_none() {
        meta.email = profile.meta.email.clone();
    }
    if meta.account_uuid.is_none() {
        meta.account_uuid = profile.meta.account_uuid.clone();
    }
    if meta.organization_uuid.is_none() {
        meta.organization_uuid = profile.meta.organization_uuid.clone();
    }
    if meta.organization_name.is_none() {
        meta.organization_name = profile.meta.organization_name.clone();
    }
    if meta.subscription_type.is_none() {
        meta.subscription_type = profile.meta.subscription_type.clone();
    }
    if meta.rate_limit_tier.is_none() {
        meta.rate_limit_tier = profile.meta.rate_limit_tier.clone();
    }
}

fn apply_oauth_profile(
    meta: &mut ProfileMeta,
    keychain_password: Option<&str>,
) -> Result<(), String> {
    let Some(raw) = keychain_password else {
        return Ok(());
    };
    let access_token = oauth_access_token_from_raw(raw)?;
    let value = cached_oauth_profile(&access_token)?;
    if let Some(account) = value.get("account") {
        meta.email = string_field(account, &["email"])
            .map(ToOwned::to_owned)
            .or(meta.email.take());
        meta.account_uuid = string_field(account, &["uuid"])
            .map(ToOwned::to_owned)
            .or(meta.account_uuid.take());
        if account
            .get("has_claude_max")
            .and_then(|item| item.as_bool())
            .unwrap_or(false)
        {
            meta.subscription_type = Some("max".to_string());
        } else if account
            .get("has_claude_pro")
            .and_then(|item| item.as_bool())
            .unwrap_or(false)
        {
            meta.subscription_type = Some("pro".to_string());
        }
    }
    if let Some(organization) = value.get("organization") {
        meta.organization_uuid = string_field(organization, &["uuid"])
            .map(ToOwned::to_owned)
            .or(meta.organization_uuid.take());
        meta.organization_name = string_field(organization, &["name"])
            .map(ToOwned::to_owned)
            .or(meta.organization_name.take());
        meta.rate_limit_tier = string_field(organization, &["rate_limit_tier"])
            .map(ToOwned::to_owned)
            .or(meta.rate_limit_tier.take());
    }
    meta.has_oauth_account = true;
    Ok(())
}

fn current_username() -> Result<String, String> {
    if let Ok(name) = std::env::var("USER") {
        let trimmed = name.trim();
        if !trimmed.is_empty() {
            return Ok(trimmed.to_string());
        }
    }
    // $USER 不可用时退回 whoami；两者都失败就报错，绝不写死某个用户名。
    let whoami = Command::new("whoami")
        .output()
        .ok()
        .and_then(|output| {
            if output.status.success() {
                Some(String::from_utf8_lossy(&output.stdout).trim().to_string())
            } else {
                None
            }
        })
        .filter(|name| !name.is_empty());
    whoami.ok_or_else(|| "无法确定当前系统用户名（$USER 与 whoami 均失败）".to_string())
}

fn hex_encode(input: &str) -> String {
    input
        .as_bytes()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>()
}

fn read_keychain_password() -> Result<Option<String>, String> {
    let username = current_username()?;
    let output = Command::new("security")
        .arg("find-generic-password")
        .arg("-a")
        .arg(&username)
        .arg("-s")
        .arg(KEYCHAIN_SERVICE)
        .arg("-w")
        .output()
        .map_err(|e| format!("读取 Keychain 失败: {e}"))?;

    if output.status.success() {
        let text = String::from_utf8_lossy(&output.stdout)
            .trim_end()
            .to_string();
        return Ok(Some(text));
    }

    // Migration fallback for early claude-switcher builds that wrote the
    // service without Claude Code's account attribute.
    let fallback = Command::new("security")
        .args(["find-generic-password", "-s", KEYCHAIN_SERVICE, "-w"])
        .output()
        .map_err(|e| format!("读取 Keychain 失败: {e}"))?;
    if fallback.status.success() {
        let text = String::from_utf8_lossy(&fallback.stdout)
            .trim_end()
            .to_string();
        return Ok(Some(text));
    }

    let stderr = String::from_utf8_lossy(&output.stderr);
    if stderr.contains("could not be found")
        || stderr.contains("The specified item could not be found")
    {
        return Ok(None);
    }
    Ok(None)
}

// ───────────────────────── C2：token 落盘加密 ─────────────────────────
//
// 设计要点：
// - 只加密「敏感字段」keychain_password（OAuth blob，唯一明文 token）；
//   claude_json / settings_json / meta 保持明文，方便调试。
// - 主密钥 32B 存独立 Keychain 项（service=STORE_KEY_KEYCHAIN_SERVICE，
//   account=当前系统用户名），缺失时用 rand 生成并 base64 写入 keychain。
// - 加密值表示：字符串 "enc:v1:" + base64(nonce(12B) || ciphertext)。
// - 向后兼容：读到的值若不以 ENC_PREFIX 开头 → 当旧明文直接用，下次 save 自然被加密。
// - nonce 每次写入都用 OsRng 重新随机生成 12B，绝不复用（GCM 安全前提）。

/// 读取（缺失则生成并写入）store 加密主密钥，返回 32 字节。
///
/// Keychain 里以 base64 字符串保存。失败一律返回清晰 Err（不 panic）。
/// 只读取现有 store 加密主密钥：不存在返回 Ok(None)，真正出错返回 Err。
///
/// **解密路径只用这个**——绝不在缺密钥时生成新密钥。否则一旦主密钥临时读不到/
/// 丢失，就会铸出新密钥、用错密钥解密、并污染恢复路径，导致已加密数据不可逆丢失。
fn read_store_key() -> Result<Option<[u8; 32]>, String> {
    let username = current_username()?;
    let output = Command::new("security")
        .arg("find-generic-password")
        .arg("-a")
        .arg(&username)
        .arg("-s")
        .arg(STORE_KEY_KEYCHAIN_SERVICE)
        .arg("-w")
        .output()
        .map_err(|e| format!("读取 store 加密密钥失败: {e}"))?;

    if !output.status.success() {
        return Ok(None);
    }
    let b64 = String::from_utf8_lossy(&output.stdout).trim().to_string();
    let bytes = BASE64
        .decode(b64.as_bytes())
        .map_err(|e| format!("store 加密密钥 base64 解码失败: {e}"))?;
    let key: [u8; 32] = bytes
        .as_slice()
        .try_into()
        .map_err(|_| "store 加密密钥长度异常（应为 32 字节）".to_string())?;
    Ok(Some(key))
}

/// **加密路径专用**：读现有密钥，缺失才用 OsRng 生成 32B 新密钥并 base64 写入 keychain。
/// 生成密钥这个副作用只允许发生在「加密新明文」时，不允许发生在解密时。
fn load_or_create_store_key() -> Result<[u8; 32], String> {
    if let Some(key) = read_store_key()? {
        return Ok(key);
    }

    let username = current_username()?;
    let mut key = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut key);
    let b64 = BASE64.encode(key);

    keychain_write(&username, STORE_KEY_KEYCHAIN_SERVICE, &b64)
        .map_err(|e| format!("写入 store 加密密钥失败: {e}"))?;
    Ok(key)
}

/// 把明文加密成 "enc:v1:" + base64(nonce(12B) || ciphertext)。
fn encrypt_secret(plaintext: &str) -> Result<String, String> {
    let key_bytes = load_or_create_store_key()?;
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&key_bytes));

    // 每次写入都重新随机生成 12B nonce，绝不复用。
    let mut nonce_bytes = [0u8; 12];
    rand::rngs::OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext = cipher
        .encrypt(nonce, plaintext.as_bytes())
        .map_err(|e| format!("加密 token 失败: {e}"))?;

    let mut blob = Vec::with_capacity(12 + ciphertext.len());
    blob.extend_from_slice(&nonce_bytes);
    blob.extend_from_slice(&ciphertext);
    Ok(format!("{ENC_PREFIX}{}", BASE64.encode(blob)))
}

/// 解密 "enc:v1:..." 字符串回明文。
/// 若不以 ENC_PREFIX 开头 → 当旧明文原样返回（向后兼容）。
/// 解密失败返回清晰 Err（不 panic）。
fn decrypt_secret(value: &str) -> Result<String, String> {
    let Some(b64) = value.strip_prefix(ENC_PREFIX) else {
        // 旧明文：原样返回，下次落盘时会被自动加密。
        return Ok(value.to_string());
    };

    let blob = BASE64
        .decode(b64.as_bytes())
        .map_err(|e| format!("解密 token 失败（base64 解码）: {e}"))?;
    if blob.len() < 12 {
        return Err("解密 token 失败：密文长度不足（缺少 nonce）".to_string());
    }
    let (nonce_bytes, ciphertext) = blob.split_at(12);
    let nonce = Nonce::from_slice(nonce_bytes);

    // 解密只读现有密钥，缺失即明确报错——绝不在这里生成新密钥（否则会用错密钥
    // 解密并污染数据）。
    let key_bytes = read_store_key()?.ok_or_else(|| {
        "解密 token 失败：找不到 store 加密主密钥（claude-switcher-store-key）。\
         可能密钥被删除 / 换机 / 系统用户名变化，已加密数据无法解开。\
         请勿在此状态下覆盖保存 store，先恢复该 Keychain 密钥项。"
            .to_string()
    })?;
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&key_bytes));
    let plaintext = cipher
        .decrypt(nonce, ciphertext)
        .map_err(|e| format!("解密 token 失败（认证/解密错误，密钥不匹配或数据被篡改）: {e}"))?;
    String::from_utf8(plaintext).map_err(|e| format!("解密 token 失败（非 UTF-8 明文）: {e}"))
}

/// 把一个可能为明文的 keychain_password 落盘前加密。
/// 已经是 "enc:v1:" 开头的（不应发生，但保险）直接透传，避免二次加密。
fn encrypt_keychain_field(value: &str) -> Result<String, String> {
    if value.starts_with(ENC_PREFIX) {
        return Ok(value.to_string());
    }
    encrypt_secret(value)
}

fn detect_clash_runtime_config() -> ClashRuntimeConfig {
    for path in clash_config_candidates().unwrap_or_default() {
        let Ok(Some(value)) = read_yaml_optional(path) else {
            continue;
        };
        let controller = string_field(&value, &["external-controller"])
            .map(ToOwned::to_owned)
            .unwrap_or_else(|| "127.0.0.1:9090".to_string());
        let controller = if controller.starts_with("http://") || controller.starts_with("https://")
        {
            controller
        } else {
            format!("http://{controller}")
        };
        let secret = string_field(&value, &["secret"])
            .filter(|s| !s.trim().is_empty())
            .map(ToOwned::to_owned);
        let proxy = numeric_field(&value, &["mixed-port"])
            .or_else(|| numeric_field(&value, &["port"]))
            .filter(|port| *port > 0)
            .map(|port| format!("http://127.0.0.1:{port}"));
        return ClashRuntimeConfig {
            controller,
            secret,
            proxy,
        };
    }

    ClashRuntimeConfig {
        controller: "http://127.0.0.1:9090".to_string(),
        secret: None,
        proxy: None,
    }
}

fn clash_api(method: &str, path: &str, body: Option<Value>) -> Result<Value, String> {
    let cfg = detect_clash_runtime_config();
    let url = format!(
        "{}/{}",
        cfg.controller.trim_end_matches('/'),
        path.trim_start_matches('/')
    );
    let mut cmd = Command::new("curl");
    cmd.arg("-sS")
        .arg("--max-time")
        .arg("8")
        .arg("-X")
        .arg(method);
    if let Some(secret) = cfg.secret {
        cmd.arg("-H").arg(format!("Authorization: Bearer {secret}"));
    }
    if let Some(body) = body {
        cmd.arg("-H")
            .arg("Content-Type: application/json")
            .arg("-d")
            .arg(body.to_string());
    }
    cmd.arg(url);

    let output = cmd
        .output()
        .map_err(|e| format!("调用 Clash 控制器失败: {e}"))?;
    if !output.status.success() {
        return Err(format!(
            "调用 Clash 控制器失败: {}",
            String::from_utf8_lossy(&output.stderr)
        ));
    }
    let stdout = String::from_utf8_lossy(&output.stdout);
    if stdout.trim().is_empty() {
        return Ok(json!({}));
    }
    serde_json::from_str(&stdout).map_err(|e| format!("Clash 返回 JSON 解析失败: {e}"))
}

fn clash_group_path(group: &str) -> String {
    format!("/proxies/{}", urlencoding::encode(group))
}

fn read_clash_group(group: &str) -> Result<Value, String> {
    clash_api("GET", &clash_group_path(group), None)
}

fn clash_status_for_group(group: &str) -> ClashStatus {
    let runtime = detect_clash_runtime_config();
    match read_clash_group(group) {
        Ok(value) => ClashStatus {
            available: true,
            controller: runtime.controller,
            group: group.to_string(),
            group_type: string_field(&value, &["type"]).map(ToOwned::to_owned),
            now: string_field(&value, &["now"]).map(ToOwned::to_owned),
            nodes: value
                .get("all")
                .and_then(|v| v.as_array())
                .map(|items| {
                    items
                        .iter()
                        .filter_map(|item| item.as_str().map(ToOwned::to_owned))
                        .collect()
                })
                .unwrap_or_default(),
            error: None,
        },
        Err(error) => ClashStatus {
            available: false,
            controller: runtime.controller,
            group: group.to_string(),
            group_type: None,
            now: None,
            nodes: Vec::new(),
            error: Some(error),
        },
    }
}

fn switch_clash_node_internal(group: &str, node: &str) -> Result<ClashSwitchResult, String> {
    let before = read_clash_group(group)?;
    let previous = string_field(&before, &["now"]).map(ToOwned::to_owned);
    let nodes = before
        .get("all")
        .and_then(|v| v.as_array())
        .map(|items| {
            items
                .iter()
                .filter_map(|item| item.as_str().map(ToOwned::to_owned))
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();

    if !nodes.iter().any(|item| item == node) {
        return Err(format!("节点「{node}」不在「{group}」组里"));
    }

    clash_api(
        "PUT",
        &clash_group_path(group),
        Some(json!({ "name": node })),
    )?;
    let after = read_clash_group(group)?;
    let now = string_field(&after, &["now"]).map(ToOwned::to_owned);
    Ok(ClashSwitchResult {
        group: group.to_string(),
        node: node.to_string(),
        previous,
        verified: now.as_deref() == Some(node),
    })
}

/// 把 value（UTF-8 文本）写入 keychain 项（account/service）。
/// 优先用 `security -i` 从 stdin 喂命令，让 payload 不出现在 argv（被 ps / 进程监控
/// 看到）——与官方 Claude Code 的做法一致；仅当命令行超过 security -i 的 stdin 行缓冲
/// （~4096B fgets）时回退 argv，避免静默截断损坏。value 一律以 -X <hex> 存储
/// （读回用 -w 即得回原文本），规避命令行转义。
fn keychain_write(account: &str, service: &str, value: &str) -> Result<(), String> {
    use std::io::Write;
    use std::process::Stdio;

    let hex = hex_encode(value);
    let command = format!("add-generic-password -U -a \"{account}\" -s \"{service}\" -X {hex}\n");
    // security -i 的 fgets 缓冲是 4096B，留 64B 余量。
    const STDIN_LINE_LIMIT: usize = 4096 - 64;

    if command.len() <= STDIN_LINE_LIMIT {
        let mut child = Command::new("security")
            .arg("-i")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| format!("写入 Keychain 失败: {e}"))?;
        child
            .stdin
            .take()
            .ok_or_else(|| "写入 Keychain 失败：无法获取 security stdin".to_string())?
            .write_all(command.as_bytes())
            .map_err(|e| format!("写入 Keychain 失败: {e}"))?;
        let out = child
            .wait_with_output()
            .map_err(|e| format!("写入 Keychain 失败: {e}"))?;
        if out.status.success() {
            return Ok(());
        }
        return Err(format!(
            "写入 Keychain 失败: {}",
            String::from_utf8_lossy(&out.stderr)
        ));
    }

    // payload 过大：回退 argv（hex 会短暂出现在 ps，但优于截断损坏）。
    let out = Command::new("security")
        .args([
            "add-generic-password",
            "-U",
            "-a",
            account,
            "-s",
            service,
            "-X",
            &hex,
        ])
        .output()
        .map_err(|e| format!("写入 Keychain 失败: {e}"))?;
    if out.status.success() {
        Ok(())
    } else {
        Err(format!(
            "写入 Keychain 失败: {}",
            String::from_utf8_lossy(&out.stderr)
        ))
    }
}

fn write_keychain_password(password: &str) -> Result<(), String> {
    let username = current_username()?;

    // 只清理 *当前用户* 名下的同名 service 项，避免误删其他 account（如别的系统用户）
    // 写在同一 service 上的钥匙串条目。
    loop {
        let output = Command::new("security")
            .args(["delete-generic-password", "-a"])
            .arg(&username)
            .args(["-s", KEYCHAIN_SERVICE])
            .output()
            .map_err(|e| format!("清理旧 Keychain 失败: {e}"))?;
        if !output.status.success() {
            break;
        }
    }

    // best-effort 清理早期 claude-switcher 误用 account="Claude Code" 写下的残留项。
    loop {
        let output = Command::new("security")
            .args(["delete-generic-password", "-a", LEGACY_KEYCHAIN_ACCOUNT])
            .args(["-s", KEYCHAIN_SERVICE])
            .output();
        match output {
            Ok(out) if out.status.success() => continue,
            _ => break,
        }
    }

    keychain_write(&username, KEYCHAIN_SERVICE, password)
}

/// live 快照三元组：(~/.claude.json, ~/.claude/settings.json, Keychain 凭据)。
/// 抽别名消掉 clippy::type_complexity，并让 BackupSnapshot / 各处签名读起来一致。
type LiveSnapshot = (Option<Value>, Option<Value>, Option<String>);

fn current_snapshot() -> Result<LiveSnapshot, String> {
    let claude_json = read_json_optional(claude_json_path()?)?;
    let settings_json = read_json_optional(claude_settings_path()?)?;
    let keychain = read_keychain_password()?;
    Ok((claude_json, settings_json, keychain))
}

/// 清空当前用户名下的 Keychain 凭据条目（回滚到「原本没有钥匙串」时用）。
/// best-effort：删不掉/本来就没有都当成成功，不要让回滚因为这步炸掉。
fn clear_keychain_password() -> Result<(), String> {
    let username = current_username()?;
    loop {
        let output = Command::new("security")
            .args(["delete-generic-password", "-a"])
            .arg(&username)
            .args(["-s", KEYCHAIN_SERVICE])
            .output()
            .map_err(|e| format!("清理 Keychain 失败: {e}"))?;
        if !output.status.success() {
            break;
        }
    }
    Ok(())
}

fn clear_legacy_keychain_password() -> Result<(), String> {
    loop {
        let output = Command::new("security")
            .args(["delete-generic-password", "-a", LEGACY_KEYCHAIN_ACCOUNT])
            .args(["-s", KEYCHAIN_SERVICE])
            .output()
            .map_err(|e| format!("清理旧 Keychain 失败: {e}"))?;
        if !output.status.success() {
            break;
        }
    }
    Ok(())
}

/// 把账号材料的某一处「写回」到 before 快照里的原值：
/// 有原值就写回去，原本不存在就删掉文件。统一给回滚用，避免回滚时把文件写成空 JSON。
fn restore_json_file(path: PathBuf, original: Option<&Value>) -> Result<(), String> {
    match original {
        Some(value) => write_json_pretty(path, value),
        None => {
            if path.exists() {
                fs::remove_file(&path).map_err(|e| e.to_string())?;
            }
            Ok(())
        }
    }
}

/// 事务回滚：用 before 快照把账号材料（~/.claude.json、settings.json、Keychain）
/// 全部还原回写动作之前的状态。
///
/// 设计要点：
/// - 这是 best-effort 的「补救」步骤，本身绝不再调用 `apply_account_material`，
///   也不依赖任何会再次触发回滚的路径，因此不存在死循环。
/// - 即便某一步还原失败，也继续尝试还原其余几处，把所有失败原因汇总返回，
///   交给调用方拼进最终错误信息。
fn rollback_account_material(snapshot: &BackupSnapshot) -> Vec<String> {
    let mut failures = Vec::new();

    match claude_json_path() {
        Ok(path) => {
            if let Err(e) = restore_json_file(path, snapshot.claude_json.as_ref()) {
                failures.push(format!("还原 ~/.claude.json 失败: {e}"));
            }
        }
        Err(e) => failures.push(format!("定位 ~/.claude.json 失败: {e}")),
    }

    match claude_settings_path() {
        Ok(path) => {
            if let Err(e) = restore_json_file(path, snapshot.settings_json.as_ref()) {
                failures.push(format!("还原 ~/.claude/settings.json 失败: {e}"));
            }
        }
        Err(e) => failures.push(format!("定位 ~/.claude/settings.json 失败: {e}")),
    }

    let keychain_result = match &snapshot.keychain {
        Some(password) => write_keychain_password(password),
        None => clear_keychain_password(),
    };
    if let Err(e) = keychain_result {
        failures.push(format!("还原 Keychain 失败: {e}"));
    }

    failures
}

/// 写账号材料的语义模式：
/// - `Merge`（switch_profile 用）：~/.claude.json 走 merge_claude_json 只覆盖账号字段，
///   保留 live 的非账号字段；`None` 的项一律「不动」（跳过）。
/// - `FullReplace`（restore_backup 用）：「回滚到备份时刻」语义——
///   ~/.claude.json / settings.json 用备份值**整体覆盖**（不 merge）；
///   备份里为 `None` 的项 → **删除**当前文件 / **清空** Keychain，而不是跳过。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum WriteMode {
    Merge,
    FullReplace,
}

/// 带事务回滚地写入账号材料：~/.claude.json、settings.json、Keychain。
/// 任一步写失败，立刻用 `rollback_from` before 快照把已经写下去的几处还原回去，
/// 再返回 Err 说明「已回滚」。
///
/// 参数：
/// - `mode`：`Merge` 合并账号字段 / `FullReplace` 整体覆盖（详见 [`WriteMode`]）；
/// - `claude_json`：要写进 ~/.claude.json 的来源；
/// - `settings`：要写入的 settings.json；
/// - `keychain`：要写入 Keychain 的凭据；
/// - `rollback_from`：调用方在写之前已经创建好的 before 快照，作为回滚源。
///
/// `None` 语义随 `mode` 不同（Merge=跳过，FullReplace=删除/清空），见上文。
///
/// 目标：不再出现「账号 JSON 已变但 settings/钥匙串没变」的半成品状态。
fn apply_account_material(
    mode: WriteMode,
    claude_json: Option<&Value>,
    settings: Option<&Value>,
    keychain: Option<&str>,
    rollback_from: &BackupSnapshot,
) -> Result<(), String> {
    // 任意一步失败：先回滚，再把「原始错误 + 回滚结果」拼成最终错误返回。
    fn fail_with_rollback(reason: String, rollback_from: &BackupSnapshot) -> String {
        let failures = rollback_account_material(rollback_from);
        if failures.is_empty() {
            format!("{reason}；已回滚到操作前状态")
        } else {
            format!("{reason}；尝试回滚但部分步骤失败：{}", failures.join("；"))
        }
    }

    // ── ~/.claude.json ──
    match (mode, claude_json) {
        (WriteMode::Merge, Some(source)) => {
            let path = match claude_json_path() {
                Ok(path) => path,
                Err(e) => {
                    return Err(fail_with_rollback(
                        format!("定位 ~/.claude.json 失败: {e}"),
                        rollback_from,
                    ))
                }
            };
            // Merge：保留 live ~/.claude.json 的非账号字段，只覆盖账号相关字段。
            let current = match read_json_optional(path.clone()) {
                Ok(current) => current,
                Err(e) => {
                    return Err(fail_with_rollback(
                        format!("读取 live ~/.claude.json 失败: {e}"),
                        rollback_from,
                    ))
                }
            };
            let next = merge_claude_json(current, source);
            if let Err(e) = write_json_pretty(path, &next) {
                return Err(fail_with_rollback(
                    format!("写入 ~/.claude.json 失败: {e}"),
                    rollback_from,
                ));
            }
        }
        (WriteMode::FullReplace, Some(source)) => {
            let path = match claude_json_path() {
                Ok(path) => path,
                Err(e) => {
                    return Err(fail_with_rollback(
                        format!("定位 ~/.claude.json 失败: {e}"),
                        rollback_from,
                    ))
                }
            };
            // FullReplace：整体覆盖，不 merge。
            if let Err(e) = write_json_pretty(path, source) {
                return Err(fail_with_rollback(
                    format!("写入 ~/.claude.json 失败: {e}"),
                    rollback_from,
                ));
            }
        }
        (WriteMode::FullReplace, None) => {
            // FullReplace 且备份里没有 claude_json：删除当前文件（回到「原本没有」）。
            let path = match claude_json_path() {
                Ok(path) => path,
                Err(e) => {
                    return Err(fail_with_rollback(
                        format!("定位 ~/.claude.json 失败: {e}"),
                        rollback_from,
                    ))
                }
            };
            if path.exists() {
                if let Err(e) = fs::remove_file(&path) {
                    return Err(fail_with_rollback(
                        format!("删除 ~/.claude.json 失败: {e}"),
                        rollback_from,
                    ));
                }
            }
        }
        (WriteMode::Merge, None) => {
            // Merge 且无来源：不动 ~/.claude.json。
        }
    }

    // ── ~/.claude/settings.json ──
    match (mode, settings) {
        (_, Some(settings)) => {
            let path = match claude_settings_path() {
                Ok(path) => path,
                Err(e) => {
                    return Err(fail_with_rollback(
                        format!("定位 ~/.claude/settings.json 失败: {e}"),
                        rollback_from,
                    ))
                }
            };
            if let Err(e) = write_json_pretty(path, settings) {
                return Err(fail_with_rollback(
                    format!("写入 ~/.claude/settings.json 失败: {e}"),
                    rollback_from,
                ));
            }
        }
        (WriteMode::FullReplace, None) => {
            // FullReplace 且备份里没有 settings：删除当前 settings.json。
            let path = match claude_settings_path() {
                Ok(path) => path,
                Err(e) => {
                    return Err(fail_with_rollback(
                        format!("定位 ~/.claude/settings.json 失败: {e}"),
                        rollback_from,
                    ))
                }
            };
            if path.exists() {
                if let Err(e) = fs::remove_file(&path) {
                    return Err(fail_with_rollback(
                        format!("删除 ~/.claude/settings.json 失败: {e}"),
                        rollback_from,
                    ));
                }
            }
        }
        (WriteMode::Merge, None) => {
            // Merge 且无 settings：不动 settings.json。
        }
    }

    // ── Keychain ──
    match (mode, keychain) {
        (_, Some(password)) => {
            if let Err(e) = write_keychain_password(password) {
                return Err(fail_with_rollback(
                    format!("写入 Keychain 失败: {e}"),
                    rollback_from,
                ));
            }
        }
        (WriteMode::FullReplace, None) => {
            // FullReplace 且备份里没有 keychain：清空 Keychain（回到「原本没有」）。
            if let Err(e) = clear_keychain_password() {
                return Err(fail_with_rollback(
                    format!("清空 Keychain 失败: {e}"),
                    rollback_from,
                ));
            }
        }
        (WriteMode::Merge, None) => {
            // Merge 且无 keychain：不动 Keychain。
        }
    }

    Ok(())
}

/// 写账号材料前用于回滚的 before 快照。
///
/// 三个字段分别是写动作前磁盘/钥匙串里的原值：
/// - `claude_json` / `settings_json` 为 `None` 表示原本文件不存在（回滚时应删除而非写空）；
/// - `keychain` 为 `None` 表示原本没有钥匙串条目（回滚时应清空而非写空）。
#[derive(Debug, Clone)]
struct BackupSnapshot {
    claude_json: Option<Value>,
    settings_json: Option<Value>,
    keychain: Option<String>,
}

impl BackupSnapshot {
    /// 从一份备份文件的 JSON（含 claude_json / settings_json / keychain_password 字段）
    /// 解出回滚快照。备份里这几项缺失/为 null 都按「原本不存在」处理。
    ///
    /// C2：备份里的 keychain_password 可能是加密值（"enc:v1:..."）或旧明文，
    /// 这里统一 decrypt_secret 解回明文——回滚/恢复时要把真正的 OAuth blob 写进
    /// 真实 Keychain，不能写加密串。解密失败返回清晰 Err（不 panic）。
    fn from_backup_value(backup: &Value) -> Result<Self, String> {
        let keychain = match backup
            .get("keychain_password")
            .and_then(|v| v.as_str())
            .filter(|s| !s.is_empty())
        {
            Some(raw) => Some(decrypt_secret(raw)?),
            None => None,
        };
        Ok(BackupSnapshot {
            claude_json: backup.get("claude_json").filter(|v| !v.is_null()).cloned(),
            settings_json: backup
                .get("settings_json")
                .filter(|v| !v.is_null())
                .cloned(),
            keychain,
        })
    }
}

fn update_profile_from_snapshot(
    profile: &mut StoredProfile,
    claude_json: Value,
    settings_json: Option<Value>,
    keychain_password: String,
) {
    profile.meta = extract_meta(Some(&claude_json), Some(keychain_password.as_str()));
    profile.claude_json = claude_json;
    profile.settings_json = settings_json;
    profile.keychain_password = Some(keychain_password);
    profile.updated_at = Utc::now();
}

/// 切换前 best-effort 回写「当前活账号」的 live 快照到它对应的 profile。
///
/// 设计原则（N1 / N2）：
/// - live 快照不完整（缺 ~/.claude.json 或缺 Keychain）→ 跳过回写，绝不用 `?` 把错误
///   传播出去阻断后续 switch；只把原因作为 warning 返回。
/// - 回写前做身份校验：live 的 oauthAccount.accountUuid 必须与该 profile.meta.account_uuid
///   一致才回写；不一致或 live 拿不到 accountUuid（无法确认身份）→ 保守跳过并 warn，
///   绝不能用别人的凭据覆盖该 profile。
///
/// 返回需要冒泡给前端的 warning 列表（可能为空）。
fn refresh_current_profile_snapshot(store: &mut Store, target_id: &str) -> Vec<String> {
    let mut warnings = Vec::new();

    let Some(current_id) = store.current_profile_id.clone() else {
        return warnings;
    };
    if current_id == target_id {
        return warnings;
    }
    let Some(profile) = store.profiles.iter_mut().find(|p| p.id == current_id) else {
        return warnings;
    };

    // best-effort 抓取 live 快照；任何一步失败都不阻断切号，只跳过回写。
    let (claude_json, settings_json, keychain_password) = match current_snapshot() {
        Ok(snapshot) => snapshot,
        Err(err) => {
            warnings.push(format!(
                "未能读取当前账号 live 快照，已跳过对「{}」的回写：{err}",
                profile.name
            ));
            return warnings;
        }
    };

    // N1：快照不完整就跳过回写。
    let Some(claude_json) = claude_json else {
        warnings.push(format!(
            "当前缺少 ~/.claude.json，已跳过对「{}」的快照回写",
            profile.name
        ));
        return warnings;
    };
    let Some(keychain_password) = keychain_password else {
        warnings.push(format!(
            "当前缺少 Keychain {KEYCHAIN_SERVICE}，已跳过对「{}」的快照回写",
            profile.name
        ));
        return warnings;
    };

    // N2：身份校验。live 拿不到 accountUuid → 无法确认身份，保守跳过。
    let Some(live_uuid) = string_field(&claude_json, &["oauthAccount", "accountUuid"]) else {
        warnings.push(format!(
            "无法从 live ~/.claude.json 读取 accountUuid，无法确认身份，已跳过对「{}」的回写",
            profile.name
        ));
        return warnings;
    };
    match profile.meta.account_uuid.as_deref() {
        Some(profile_uuid) if profile_uuid == live_uuid => {
            update_profile_from_snapshot(profile, claude_json, settings_json, keychain_password);
        }
        _ => {
            warnings.push(format!(
                "当前 live 身份（accountUuid={live_uuid}）与账号「{}」不一致，可能是手动登录了别的号，已跳过回写以免覆盖凭据",
                profile.name
            ));
        }
    }

    warnings
}

fn create_backup_with_label(label: &str) -> Result<BackupResult, String> {
    ensure_app_dirs()?;
    let (claude_json, settings_json, keychain_password) = current_snapshot()?;
    // C2：备份文件里的 keychain_password 同样加密落盘（claude_json/settings 保持明文）。
    let keychain_password = match keychain_password {
        Some(plain) => Some(encrypt_keychain_field(&plain)?),
        None => None,
    };
    let id = format!("{}-{}", Utc::now().format("%Y%m%d%H%M%S"), Uuid::new_v4());
    let path = backups_dir()?.join(format!("{id}.json"));
    let backup = json!({
        "id": id,
        "label": label,
        "created_at": Utc::now(),
        "claude_json": claude_json,
        "settings_json": settings_json,
        "keychain_password": keychain_password,
    });
    write_json_pretty(path.clone(), &backup)?;
    // H4：成功落盘后只保留最近 30 个备份，best-effort 清理旧的，不阻断主流程。
    prune_backups(30);
    Ok(BackupResult {
        id,
        path: path.to_string_lossy().to_string(),
        created_at: Utc::now(),
    })
}

/// 把已落盘的备份文件（按路径）读回成回滚快照。
/// 给 switch_profile / restore_backup 复用「它们刚创建的 before-* 备份」做回滚源。
fn load_backup_snapshot(path: &PathBuf) -> Result<BackupSnapshot, String> {
    let raw = fs::read_to_string(path).map_err(|e| format!("读取备份失败: {e}"))?;
    let backup: Value =
        serde_json::from_str(&raw).map_err(|e| format!("备份 JSON 解析失败: {e}"))?;
    BackupSnapshot::from_backup_value(&backup)
}

/// best-effort 清理 backups 目录，只保留最近 `keep` 个 `.json` 备份。
/// 任何 IO 错误都静默忽略——清理失败不应影响备份/切号主流程。
fn prune_backups(keep: usize) {
    let Ok(dir) = backups_dir() else {
        return;
    };
    let Ok(entries) = fs::read_dir(&dir) else {
        return;
    };

    // 收集 (排序键, 路径)。排序键优先用文件名（备份名以 %Y%m%d%H%M%S 时间戳开头，
    // 字典序即时间序），mtime 作为兜底辅助。
    let mut files: Vec<(String, std::time::SystemTime, PathBuf)> = entries
        .filter_map(|entry| entry.ok())
        .map(|entry| entry.path())
        .filter(|path| path.is_file() && path.extension().and_then(|e| e.to_str()) == Some("json"))
        .map(|path| {
            let name = path
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("")
                .to_string();
            let mtime = path
                .metadata()
                .and_then(|m| m.modified())
                .unwrap_or(std::time::SystemTime::UNIX_EPOCH);
            (name, mtime, path)
        })
        .collect();

    if files.len() <= keep {
        return;
    }

    // 升序排序（最旧在前）：先按文件名（时间戳）字典序，再按 mtime。
    files.sort_by(|a, b| a.0.cmp(&b.0).then_with(|| a.1.cmp(&b.1)));

    let remove_count = files.len() - keep;
    for (_, _, path) in files.into_iter().take(remove_count) {
        let _ = fs::remove_file(path);
    }
}

/// H2：best-effort 检测 Claude Code CLI 是否在运行（仅用于提示重启，非阻断）。
/// 尽量精确匹配 Claude Code CLI 进程，避免把本工具（claude-switcher）自身误判进来。
fn claude_code_processes() -> Vec<(u32, String)> {
    // pgrep -f -l 输出 "pid command"，便于过滤掉 claude-switcher 自身。
    let Ok(output) = Command::new("pgrep").args(["-f", "-l", "claude"]).output() else {
        return Vec::new();
    };
    if !output.status.success() {
        return Vec::new();
    }
    let text = String::from_utf8_lossy(&output.stdout);
    text.lines()
        .filter_map(|line| {
            let (pid_raw, command) = line.split_once(char::is_whitespace)?;
            let pid = pid_raw.parse::<u32>().ok()?;
            let command = command.trim().to_string();
            let lower = command.to_ascii_lowercase();
            // 命中 Claude Code CLI（"claude" 可执行 / @anthropic-ai/claude-code），
            // 但排除本工具自身与 macOS 桌面版 Claude.app 之类的无关进程。
            let is_self = lower.contains("claude-switcher") || lower.contains("claude_switcher");
            if is_self {
                return None;
            }
            let is_claude_code = lower.contains("claude-code")
                || lower.contains("claude code")
                || lower.split_whitespace().any(|tok| {
                    let base = tok.rsplit('/').next().unwrap_or(tok);
                    base == "claude"
                });
            is_claude_code.then_some((pid, command))
        })
        .collect()
}

fn claude_code_running() -> bool {
    !claude_code_processes().is_empty()
}

fn kill_claude_code_processes() -> Result<Vec<String>, String> {
    let processes = claude_code_processes();
    if processes.is_empty() {
        return Ok(Vec::new());
    }

    let pids = processes
        .iter()
        .map(|(pid, _)| pid.to_string())
        .collect::<Vec<_>>();
    let _ = Command::new("kill").args(&pids).output();
    thread::sleep(StdDuration::from_millis(600));

    let remaining = claude_code_processes();
    if !remaining.is_empty() {
        let remaining_pids = remaining
            .iter()
            .map(|(pid, _)| pid.to_string())
            .collect::<Vec<_>>();
        let output = Command::new("kill")
            .arg("-9")
            .args(&remaining_pids)
            .output()
            .map_err(|e| format!("强制结束 Claude Code 进程失败: {e}"))?;
        if !output.status.success() {
            return Err(format!(
                "强制结束 Claude Code 进程失败: {}",
                String::from_utf8_lossy(&output.stderr)
            ));
        }
        thread::sleep(StdDuration::from_millis(300));
    }

    let still_running = claude_code_processes();
    if !still_running.is_empty() {
        return Err(format!(
            "仍有 Claude Code 进程未退出: {}",
            still_running
                .iter()
                .map(|(pid, command)| format!("{pid} {command}"))
                .collect::<Vec<_>>()
                .join("；")
        ));
    }

    Ok(vec![format!(
        "已结束 {} 个 Claude Code 进程：{}",
        processes.len(),
        processes
            .iter()
            .map(|(pid, _)| pid.to_string())
            .collect::<Vec<_>>()
            .join(", ")
    )])
}

/// N3：检测 ~/.claude/settings.json 是否含 apiKeyHelper 字段（会覆盖 OAuth，使切号失效）。
fn settings_has_api_key_helper() -> bool {
    let Ok(path) = claude_settings_path() else {
        return false;
    };
    match read_json_optional(path) {
        Ok(Some(value)) => value
            .get("apiKeyHelper")
            .map(|v| !v.is_null())
            .unwrap_or(false),
        _ => false,
    }
}

/// 遥测去关联核心 helper（幂等）：把 `mode` 对应的隐私 env 合并/清理进
/// ~/.claude/settings.json 的 "env" 字段，让用户启动的 Claude Code 关闭把同设备
/// 多账号串起来的遥测。
///
/// 语义（严格只动这两个 key，不碰 settings.env 里其它 key、也不碰 settings 其它字段）：
/// 1. settings.json 不存在 → 当空对象 `{}`；确保 settings 是 object、settings.env 是 object。
/// 2. 先从 settings.env **删除** DISABLE_TELEMETRY 和
///    CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC 两个 key（保证互斥 + 切模式时净清理）。
/// 3. 再按 `mode` 加回对应 key（值 "1"）；`Default` 模式两个都不加（净删除）。
/// 4. 固化默认权限模式 permissions.defaultMode=bypassPermissions，保留 permissions
///    下其它字段（如 deny）不动。
/// 5. 收尾：若 settings.env 变空则把空 "env" 对象删掉；最终 settings 非空才写回
///    （write_json_pretty，权限 600）。
///
/// 注意：现在会默认写入 permissions.defaultMode，因此 settings.json 不存在时也会创建。
fn ensure_default_permissions(settings: &mut Value) {
    if !settings.is_object() {
        *settings = json!({});
    }
    let obj = settings.as_object_mut().expect("settings 已确保为 object");
    let needs_reset = obj
        .get("permissions")
        .map(|value| !value.is_object())
        .unwrap_or(true);
    if needs_reset {
        obj.insert("permissions".to_string(), json!({}));
    }
    let permissions = obj
        .get_mut("permissions")
        .and_then(|value| value.as_object_mut())
        .expect("settings.permissions 已确保为 object");
    permissions.insert("defaultMode".to_string(), json!("bypassPermissions"));
}

fn apply_profile_env_to_settings(
    mode: TelemetryMode,
    runtime: Option<&ProfileRuntimeBinding>,
) -> Result<(), String> {
    let path = claude_settings_path()?;

    // 读现有 settings；不存在则当空对象 {}。
    let mut settings = match read_json_optional(path.clone())? {
        Some(value) => value,
        None => json!({}),
    };
    // 确保 settings 顶层是 object（非 object 一律重置为空对象，避免污染）。
    if !settings.is_object() {
        settings = json!({});
    }

    // 确保 settings.env 是 object（缺失或非 object 都重建为空对象）。
    {
        let obj = settings.as_object_mut().expect("settings 已确保为 object");
        let needs_reset = obj.get("env").map(|v| !v.is_object()).unwrap_or(true);
        if needs_reset {
            obj.insert("env".to_string(), json!({}));
        }
    }

    // 先从 settings.env 把两个隐私 key 删干净（互斥 + 净清理），再按模式加回对应的。
    {
        let env_obj = settings
            .get_mut("env")
            .and_then(|v| v.as_object_mut())
            .expect("settings.env 已确保为 object");
        env_obj.remove(ENV_DISABLE_TELEMETRY);
        env_obj.remove(ENV_DISABLE_NONESSENTIAL_TRAFFIC);
        for key in PROFILE_ENV_KEYS {
            env_obj.remove(*key);
        }
        if let Some(key) = mode.env_key() {
            env_obj.insert(key.to_string(), json!("1"));
        }
        if let Some(runtime) = runtime {
            if let Some(timezone) = runtime
                .timezone
                .as_deref()
                .filter(|value| !value.trim().is_empty())
            {
                env_obj.insert("TZ".to_string(), json!(timezone.trim()));
            }
            if let Some(locale) = runtime
                .locale
                .as_deref()
                .filter(|value| !value.trim().is_empty())
            {
                let locale = locale.trim();
                env_obj.insert("LANG".to_string(), json!(locale));
                env_obj.insert("LC_ALL".to_string(), json!(locale));
            }
        }
        // Default 模式：两个都不加（净删除）。
    }

    // 收尾：如果 settings.env 变空了，把这个空 "env" 对象删掉，别留空壳。
    {
        let obj = settings.as_object_mut().expect("settings 仍为 object");
        let env_empty = obj
            .get("env")
            .and_then(|v| v.as_object())
            .map(|m| m.is_empty())
            .unwrap_or(false);
        if env_empty {
            obj.remove("env");
        }
    }

    ensure_default_permissions(&mut settings);

    // 写回策略：
    // permissions.defaultMode 是工具默认保障，因此这里总是写回。
    write_json_pretty(path, &settings)
}

fn scrub_auth_from_settings(settings: Option<Value>) -> Option<Value> {
    let mut settings = settings.unwrap_or_else(|| json!({}));
    if !settings.is_object() {
        settings = json!({});
    }
    if let Some(obj) = settings.as_object_mut() {
        obj.remove("apiKeyHelper");
        if let Some(env) = obj.get_mut("env").and_then(|value| value.as_object_mut()) {
            for key in AUTH_ENV_KEYS {
                env.remove(*key);
            }
        }
        let env_empty = obj
            .get("env")
            .and_then(|value| value.as_object())
            .map(|env| env.is_empty())
            .unwrap_or(false);
        if env_empty {
            obj.remove("env");
        }
        if obj.is_empty() {
            return None;
        }
    }
    Some(settings)
}

fn remove_legacy_credentials_file() -> Result<(), String> {
    let path = legacy_credentials_path()?;
    if path.exists() {
        fs::remove_file(&path)
            .map_err(|e| format!("删除 ~/.claude/.credentials.json 失败: {e}"))?;
    }
    Ok(())
}

fn clean_live_account_for_new_login(
    settings_json: Option<Value>,
    rollback_from: &BackupSnapshot,
) -> Result<(), String> {
    let scrubbed_settings = scrub_auth_from_settings(settings_json);
    apply_account_material(
        WriteMode::FullReplace,
        None,
        scrubbed_settings.as_ref(),
        None,
        rollback_from,
    )?;
    clear_legacy_keychain_password()?;
    remove_legacy_credentials_file()?;
    Ok(())
}

fn shell_single_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\\''"))
}

fn open_clean_claude_login_terminal(runtime: Option<&ProfileRuntimeBinding>) -> Result<(), String> {
    let mut parts = vec![
        "cd ~".to_string(),
        "env".to_string(),
        "-u ANTHROPIC_API_KEY".to_string(),
        "-u ANTHROPIC_AUTH_TOKEN".to_string(),
        "-u CLAUDE_CODE_OAUTH_TOKEN".to_string(),
        "-u CLAUDE_CODE_OAUTH_TOKEN_FILE_DESCRIPTOR".to_string(),
        "-u CLAUDE_CODE_API_KEY_FILE_DESCRIPTOR".to_string(),
    ];
    if let Some(proxy) = detect_clash_runtime_config().proxy {
        parts.push(format!("HTTPS_PROXY={}", shell_single_quote(&proxy)));
        parts.push(format!("HTTP_PROXY={}", shell_single_quote(&proxy)));
        parts.push(format!("ALL_PROXY={}", shell_single_quote(&proxy)));
    }
    if let Some(runtime) = runtime {
        if let Some(timezone) = runtime
            .timezone
            .as_deref()
            .filter(|value| !value.trim().is_empty())
        {
            parts.push(format!("TZ={}", shell_single_quote(timezone.trim())));
        }
        if let Some(locale) = runtime
            .locale
            .as_deref()
            .filter(|value| !value.trim().is_empty())
        {
            let locale = shell_single_quote(locale.trim());
            parts.push(format!("LANG={locale}"));
            parts.push(format!("LC_ALL={locale}"));
        }
    }
    parts.push("claude".to_string());
    let terminal_command = parts.join(" ");
    let script = format!(
        "tell application \"Terminal\"\nactivate\ndo script {}\nend tell",
        shell_single_quote(&terminal_command)
    );
    let output = Command::new("osascript")
        .arg("-e")
        .arg(script)
        .output()
        .map_err(|e| format!("打开 Terminal 登录窗口失败: {e}"))?;
    if output.status.success() {
        Ok(())
    } else {
        Err(format!(
            "打开 Terminal 登录窗口失败: {}",
            String::from_utf8_lossy(&output.stderr)
        ))
    }
}

fn open_chrome_profile(profile: &str, url: &str) -> Result<(), String> {
    let profile = profile.trim();
    if profile.is_empty() {
        return Ok(());
    }
    let output = Command::new("open")
        .args(["-na", "Google Chrome", "--args"])
        .arg(format!("--profile-directory={profile}"))
        .arg(url)
        .output()
        .map_err(|e| format!("打开 Chrome Profile 失败: {e}"))?;
    if output.status.success() {
        Ok(())
    } else {
        Err(format!(
            "打开 Chrome Profile 失败: {}",
            String::from_utf8_lossy(&output.stderr)
        ))
    }
}

#[tauri::command]
fn get_status() -> Result<ClaudeStatus, String> {
    ensure_app_dirs()?;
    let store = load_store()?;
    let claude_json = read_json_optional(claude_json_path()?)?;
    let settings_json = read_json_optional(claude_settings_path()?)?;
    let keychain = read_keychain_password()?;
    let keychain_parse_ok = keychain
        .as_ref()
        .map(|raw| serde_json::from_str::<Value>(raw).is_ok())
        .unwrap_or(false);
    let mut meta = extract_meta(claude_json.as_ref(), keychain.as_deref());
    fill_meta_from_saved_profile(&mut meta, &store);
    let mut warnings = Vec::new();
    let _ = apply_oauth_profile(&mut meta, keychain.as_deref());

    if claude_json.is_none() {
        warnings.push("没有发现 ~/.claude.json，可能尚未登录 Claude Code".to_string());
    }
    if keychain.is_none() {
        warnings.push("没有发现 Keychain Claude Code-credentials".to_string());
    }
    if keychain.is_some() && !keychain_parse_ok {
        warnings.push("Keychain 内容存在但不是可解析 JSON".to_string());
    }
    if legacy_credentials_path()?.exists() {
        warnings.push("发现 ~/.claude/.credentials.json，请确认是否为旧版残留".to_string());
    }
    let auth_envs = AUTH_ENV_KEYS
        .iter()
        .filter(|key| std::env::var_os(key).is_some())
        .copied()
        .collect::<Vec<_>>();
    if !auth_envs.is_empty() {
        warnings.push(format!(
            "检测到认证环境变量 {}，Claude Code 可能会忽略 Keychain OAuth，切号可能对当前环境无效",
            auth_envs.join(", ")
        ));
    }
    if settings_has_api_key_helper() {
        warnings.push(
            "~/.claude/settings.json 含 apiKeyHelper 字段，会覆盖 Keychain OAuth，切号可能无效"
                .to_string(),
        );
    }

    let current_profile_id_ref = store.current_profile_id.as_deref();
    let session_isolation = session_isolation_status(current_profile_id_ref)?;
    if store.current_profile_id.is_some()
        && store.pending_new_account.is_none()
        && !session_isolation.enabled
    {
        warnings.push(
            "Claude session 隔离未激活；切换一次当前账号或重新捕获账号后会自动接管 ~/.claude/projects"
                .to_string(),
        );
    }

    Ok(ClaudeStatus {
        claude_json_exists: claude_json_path()?.exists(),
        settings_json_exists: settings_json.is_some(),
        credentials_json_exists: legacy_credentials_path()?.exists(),
        keychain_exists: keychain.is_some(),
        keychain_parse_ok,
        meta,
        claude_json_path: claude_json_path()?.to_string_lossy().to_string(),
        settings_json_path: claude_settings_path()?.to_string_lossy().to_string(),
        data_dir: app_data_dir()?.to_string_lossy().to_string(),
        backup_dir: backups_dir()?.to_string_lossy().to_string(),
        session_isolation,
        profile_count: store.profiles.len(),
        current_profile_name: store
            .current_profile_id
            .as_deref()
            .and_then(|id| store.profiles.iter().find(|profile| profile.id == id))
            .map(|profile| profile.name.clone()),
        pending_new_account: store.pending_new_account.clone(),
        current_profile_id: store.current_profile_id,
        telemetry_mode: store.telemetry_mode,
        warnings,
    })
}

/// 设置遥测去关联模式：解析 `mode`（非法值报错）→ 持久化进 Store（save_store）→
/// **立即**把对应隐私 env 合并/清理进当前 ~/.claude/settings.json。
///
/// 选型说明：get 端把 telemetry_mode 并进了 get_status() 的返回（ClaudeStatus.telemetry_mode），
/// 因此这里只提供 set 命令，不再单独加 get_telemetry_mode()。
#[tauri::command]
fn set_telemetry_mode(mode: String) -> Result<(), String> {
    // 解析前后端契约里的 camelCase 字符串；非法值明确报错。
    let parsed = match mode.trim() {
        "default" => TelemetryMode::Default,
        "disableTelemetry" => TelemetryMode::DisableTelemetry,
        "essentialOnly" => TelemetryMode::EssentialOnly,
        other => {
            return Err(format!(
                "非法的遥测模式「{other}」，只接受 default / disableTelemetry / essentialOnly"
            ))
        }
    };

    // 先持久化进 store，再立即落地到 settings.json（顺序：先存意图，后写文件）。
    let mut store = load_store()?;
    store.telemetry_mode = parsed;
    let runtime = store
        .pending_new_account
        .as_ref()
        .map(|pending| pending.runtime.clone())
        .or_else(|| {
            store.current_profile_id.as_deref().and_then(|id| {
                store
                    .profiles
                    .iter()
                    .find(|profile| profile.id == id)
                    .and_then(|profile| profile.runtime.clone())
            })
        });
    save_store(&store)?;
    apply_profile_env_to_settings(parsed, runtime.as_ref())
}

#[tauri::command]
fn list_profiles() -> Result<Vec<ProfileSummary>, String> {
    let store = load_store()?;
    Ok(store
        .profiles
        .iter()
        .map(|p| ProfileSummary {
            id: p.id.clone(),
            name: p.name.clone(),
            notes: p.notes.clone(),
            created_at: p.created_at,
            updated_at: p.updated_at,
            last_switched_at: p.last_switched_at,
            meta: p.meta.clone(),
            clash: p.clash.clone(),
            runtime: p.runtime.clone(),
            is_current: store.current_profile_id.as_deref() == Some(&p.id),
        })
        .collect())
}

#[tauri::command]
fn capture_current_profile(name: String, notes: Option<String>) -> Result<ProfileSummary, String> {
    let clean_name = name.trim();
    if clean_name.is_empty() {
        return Err("账号名称不能为空".to_string());
    }
    let (claude_json, settings_json, keychain_password) = current_snapshot()?;
    let claude_json =
        claude_json.ok_or_else(|| "当前没有 ~/.claude.json，无法创建账号快照".to_string())?;
    if keychain_password.is_none() {
        return Err("当前没有 Keychain Claude Code-credentials，无法创建完整快照".to_string());
    }

    let mut store = load_store()?;
    let now = Utc::now();
    let runtime = default_runtime_for_profile(clean_name, None);
    let profile = StoredProfile {
        id: Uuid::new_v4().to_string(),
        name: clean_name.to_string(),
        notes,
        created_at: now,
        updated_at: now,
        last_switched_at: None,
        meta: extract_meta(Some(&claude_json), keychain_password.as_deref()),
        claude_json,
        settings_json,
        keychain_password,
        clash: None,
        runtime: Some(runtime),
    };
    let summary = ProfileSummary {
        id: profile.id.clone(),
        name: profile.name.clone(),
        notes: profile.notes.clone(),
        created_at: profile.created_at,
        updated_at: profile.updated_at,
        last_switched_at: profile.last_switched_at,
        meta: profile.meta.clone(),
        clash: profile.clash.clone(),
        runtime: profile.runtime.clone(),
        // 下面会把 current_profile_id 指向这个新建 profile，所以它就是当前账号。
        is_current: true,
    };
    let profile_id = profile.id.clone();
    adopt_live_claude_local_state_for_profile(&profile_id)?;
    activate_profile_claude_local_state(&profile_id)?;
    store.current_profile_id = Some(profile_id);
    store.profiles.push(profile);
    save_store(&store)?;
    Ok(summary)
}

#[tauri::command]
fn prepare_new_account_login(
    name: String,
    notes: Option<String>,
    node: String,
    timezone: Option<String>,
    locale: Option<String>,
    chrome_profile: Option<String>,
) -> Result<PrepareNewAccountResult, String> {
    let clean_name = name.trim();
    if clean_name.is_empty() {
        return Err("新账号名称不能为空".to_string());
    }
    let clean_node = node.trim();
    if clean_node.is_empty() {
        return Err("必须选择新账号绑定的 Clash 节点".to_string());
    }

    let mut store = load_store()?;
    let mut warnings = Vec::new();
    if store.pending_new_account.is_some() {
        return Err("已有待完成的新号登录流程，请先完成保存或切回旧账号重新开始".to_string());
    }
    warnings.extend(kill_claude_code_processes()?);

    let backup = create_backup_with_label("before-new-account-login")?;
    warnings.extend(refresh_current_profile_snapshot(
        &mut store,
        "__new_account_login__",
    ));
    if let Some(current_id) = store.current_profile_id.as_deref() {
        warnings.extend(adopt_live_claude_local_state_for_profile(current_id)?);
    }

    let (_, settings_json, _) = current_snapshot()?;
    let rollback_from = load_backup_snapshot(&PathBuf::from(&backup.path))?;
    let clash = switch_clash_node_internal(DEFAULT_CLASH_GROUP, clean_node)?;
    let mut runtime = default_runtime_for_profile(clean_name, Some(clean_node));
    if timezone
        .as_deref()
        .map(|value| !value.trim().is_empty())
        .unwrap_or(false)
    {
        runtime.timezone = timezone.map(|value| value.trim().to_string());
    }
    if locale
        .as_deref()
        .map(|value| !value.trim().is_empty())
        .unwrap_or(false)
    {
        runtime.locale = locale.map(|value| value.trim().to_string());
    }
    if chrome_profile
        .as_deref()
        .map(|value| !value.trim().is_empty())
        .unwrap_or(false)
    {
        runtime.chrome_profile = chrome_profile.map(|value| value.trim().to_string());
    }

    let pending = PendingNewAccount {
        id: format!("pending-{}", Uuid::new_v4()),
        name: clean_name.to_string(),
        notes,
        group: DEFAULT_CLASH_GROUP.to_string(),
        node: clean_node.to_string(),
        runtime,
        created_at: Utc::now(),
    };
    clean_live_account_for_new_login(settings_json, &rollback_from)?;
    if let Err(e) = apply_profile_env_to_settings(store.telemetry_mode, Some(&pending.runtime)) {
        warnings.push(format!(
            "隐私 env 注入失败（可在设置里重选遥测模式重试）：{e}"
        ));
    }
    warnings.extend(activate_profile_claude_local_state(&pending.id)?);
    store.pending_new_account = Some(pending.clone());
    save_store(&store)?;
    if let Some(profile) = pending.runtime.chrome_profile.as_deref() {
        if let Err(e) = open_chrome_profile(profile, "https://claude.ai") {
            warnings.push(e);
        }
    }
    if let Err(e) = open_clean_claude_login_terminal(Some(&pending.runtime)) {
        warnings.push(e);
    }
    Ok(PrepareNewAccountResult {
        pending,
        backup,
        clash,
        warnings,
    })
}

#[tauri::command]
fn complete_new_account_login() -> Result<ProfileSummary, String> {
    let mut store = load_store()?;
    let pending = store
        .pending_new_account
        .clone()
        .ok_or_else(|| "没有待完成的新号登录流程".to_string())?;
    let (claude_json, settings_json, keychain_password) = current_snapshot()?;
    let claude_json = claude_json
        .ok_or_else(|| "当前没有 ~/.claude.json，请先在刚打开的 Claude 窗口完成登录".to_string())?;
    let keychain_password = keychain_password.ok_or_else(|| {
        "当前没有 Keychain Claude Code-credentials，请先完成 Claude OAuth 登录".to_string()
    })?;

    if store
        .profiles
        .iter()
        .any(|profile| profile.id == pending.id)
    {
        return Err("这个待完成账号已经保存过".to_string());
    }
    let now = Utc::now();
    let profile = StoredProfile {
        id: pending.id.clone(),
        name: pending.name.clone(),
        notes: pending.notes.clone(),
        created_at: pending.created_at,
        updated_at: now,
        last_switched_at: Some(now),
        meta: extract_meta(Some(&claude_json), Some(&keychain_password)),
        claude_json,
        settings_json,
        keychain_password: Some(keychain_password),
        clash: Some(ProfileClashBinding {
            enabled: true,
            group: pending.group.clone(),
            node: pending.node.clone(),
        }),
        runtime: Some(pending.runtime.clone()),
    };
    let summary = ProfileSummary {
        id: profile.id.clone(),
        name: profile.name.clone(),
        notes: profile.notes.clone(),
        created_at: profile.created_at,
        updated_at: profile.updated_at,
        last_switched_at: profile.last_switched_at,
        meta: profile.meta.clone(),
        clash: profile.clash.clone(),
        runtime: profile.runtime.clone(),
        is_current: true,
    };
    activate_profile_claude_local_state(&profile.id)?;
    store.current_profile_id = Some(profile.id.clone());
    store.pending_new_account = None;
    store.profiles.push(profile);
    save_store(&store)?;
    Ok(summary)
}

fn merge_claude_json(current: Option<Value>, saved: &Value) -> Value {
    let mut target = current.unwrap_or_else(|| json!({}));
    if !target.is_object() {
        target = json!({});
    }

    let keys = [
        "userID",
        "oauthAccount",
        "firstStartTime",
        "hasCompletedOnboarding",
        "lastReleaseNotesSeen",
    ];
    for key in keys {
        if let Some(value) = saved.get(key) {
            target[key] = value.clone();
        } else if let Some(obj) = target.as_object_mut() {
            obj.remove(key);
        }
    }
    target
}

#[tauri::command]
fn switch_profile(id: String) -> Result<SwitchResult, String> {
    let mut store = load_store()?;
    if !store.profiles.iter().any(|p| p.id == id) {
        return Err("找不到这个账号快照".to_string());
    }
    let mut warnings = Vec::new();

    // H2：切号前 best-effort 检测 Claude Code 是否在运行（非阻断）。
    if claude_code_running() {
        warnings.push(
            "检测到 Claude Code 仍在运行，切换不会作用于已运行的会话，请切换后重启 Claude Code"
                .to_string(),
        );
    }

    let backup = create_backup_with_label(&format!("before-switch-to-{id}"))?;
    // N1/N2：回写当前账号快照是 best-effort，不会阻断切号，只把跳过原因作为 warning 返回。
    warnings.extend(refresh_current_profile_snapshot(&mut store, &id));
    if let Some(current_id) = store.current_profile_id.as_deref() {
        warnings.extend(adopt_live_claude_local_state_for_profile(current_id)?);
    }
    let idx = store
        .profiles
        .iter()
        .position(|p| p.id == id)
        .ok_or_else(|| "找不到这个账号快照".to_string())?;
    let profile = store.profiles[idx].clone();

    let clash_result = if let Some(binding) = &profile.clash {
        if binding.enabled {
            Some(switch_clash_node_internal(&binding.group, &binding.node)?)
        } else {
            None
        }
    } else {
        None
    };

    // 事务化写入账号材料：用刚创建的 before-switch 备份做回滚源，
    // 任一步写失败都会把 ~/.claude.json / settings.json / Keychain 整体还原，
    // 杜绝「JSON 已改但 settings/钥匙串没改」的半成品状态。
    let rollback_from = load_backup_snapshot(&PathBuf::from(&backup.path))?;
    apply_account_material(
        // switch 维持 merge 语义不变：只覆盖账号字段，保留 live 的非账号字段。
        WriteMode::Merge,
        Some(&profile.claude_json),
        profile.settings_json.as_ref(),
        profile.keychain_password.as_deref(),
        &rollback_from,
    )?;

    // 保持性：profile 自带的 settings_json 可能不含隐私 env，切号刚写完 settings 后
    // 立即按 store 当前 telemetry_mode 把隐私 env 合并回去，避免切号把去关联冲掉。
    // 已过事务回滚保护区、账号材料已成功落盘——隐私 env 注入失败属非关键，best-effort：
    // 只记 warning，不让整个切号返回 Err（否则会出现「其实已切但 UI 报失败」的半成品态）。
    if let Err(e) = apply_profile_env_to_settings(store.telemetry_mode, profile.runtime.as_ref()) {
        warnings.push(format!(
            "隐私 env 注入失败（可在设置里重选遥测模式重试）：{e}"
        ));
    }
    warnings.extend(activate_profile_claude_local_state(&profile.id)?);

    store.current_profile_id = Some(profile.id.clone());
    store.profiles[idx].last_switched_at = Some(Utc::now());
    store.profiles[idx].updated_at = Utc::now();
    save_store(&store)?;

    Ok(SwitchResult {
        switched_to: profile.name,
        backup,
        clash: clash_result,
        restart_hint: "切换已写入磁盘和 Keychain；请重启正在运行的 Claude Code 会话。".to_string(),
        warnings,
    })
}

#[tauri::command]
fn get_clash_status() -> Result<ClashStatus, String> {
    Ok(clash_status_for_group(DEFAULT_CLASH_GROUP))
}

#[tauri::command]
async fn get_claude_usage() -> Result<ClaudeUsageSnapshot, String> {
    tauri::async_runtime::spawn_blocking(claude_usage_snapshot)
        .await
        .map_err(|e| format!("Claude 用量后台任务失败: {e}"))?
}

#[tauri::command]
fn switch_clash_node(group: String, node: String) -> Result<ClashSwitchResult, String> {
    switch_clash_node_internal(group.trim(), node.trim())
}

#[tauri::command]
fn switch_profile_clash_node(id: String) -> Result<ClashSwitchResult, String> {
    let store = load_store()?;
    let profile = store
        .profiles
        .iter()
        .find(|p| p.id == id)
        .ok_or_else(|| "找不到这个账号快照".to_string())?;
    let binding = profile
        .clash
        .as_ref()
        .ok_or_else(|| "这个账号还没有绑定 Clash 节点".to_string())?;
    if !binding.enabled {
        return Err("这个账号的 Clash 绑定未启用".to_string());
    }
    switch_clash_node_internal(&binding.group, &binding.node)
}

#[tauri::command]
fn set_profile_clash_binding(
    id: String,
    enabled: bool,
    group: String,
    node: String,
) -> Result<(), String> {
    let mut store = load_store()?;
    let profile = store
        .profiles
        .iter_mut()
        .find(|p| p.id == id)
        .ok_or_else(|| "找不到这个账号快照".to_string())?;
    let group = group.trim();
    let node = node.trim();
    if enabled {
        if group.is_empty() {
            return Err("Clash 组不能为空".to_string());
        }
        if node.is_empty() {
            return Err("Clash 节点不能为空".to_string());
        }
        profile.clash = Some(ProfileClashBinding {
            enabled,
            group: group.to_string(),
            node: node.to_string(),
        });
    } else {
        profile.clash = None;
    }
    profile.updated_at = Utc::now();
    save_store(&store)
}

#[tauri::command]
fn set_profile_runtime_binding(
    id: String,
    timezone: Option<String>,
    locale: Option<String>,
    chrome_profile: Option<String>,
) -> Result<(), String> {
    let mut store = load_store()?;
    let current = store.current_profile_id.as_deref() == Some(id.as_str());
    let telemetry_mode = store.telemetry_mode;
    let runtime = ProfileRuntimeBinding {
        timezone: timezone
            .map(|value| value.trim().to_string())
            .filter(|value| !value.is_empty()),
        locale: locale
            .map(|value| value.trim().to_string())
            .filter(|value| !value.is_empty()),
        chrome_profile: chrome_profile
            .map(|value| value.trim().to_string())
            .filter(|value| !value.is_empty()),
    };
    let profile = store
        .profiles
        .iter_mut()
        .find(|p| p.id == id)
        .ok_or_else(|| "找不到这个账号快照".to_string())?;
    profile.runtime = Some(runtime.clone());
    profile.updated_at = Utc::now();
    save_store(&store)?;
    if current {
        apply_profile_env_to_settings(telemetry_mode, Some(&runtime))?;
    }
    Ok(())
}

#[tauri::command]
fn delete_profile(id: String) -> Result<(), String> {
    let mut store = load_store()?;
    let before = store.profiles.len();
    store.profiles.retain(|p| p.id != id);
    if store.profiles.len() == before {
        return Err("找不到这个账号快照".to_string());
    }
    if store.current_profile_id.as_deref() == Some(&id) {
        store.current_profile_id = None;
    }
    save_store(&store)
}

#[tauri::command]
fn rename_profile(id: String, name: String, notes: Option<String>) -> Result<(), String> {
    let mut store = load_store()?;
    let clean_name = name.trim();
    if clean_name.is_empty() {
        return Err("账号名称不能为空".to_string());
    }
    let profile = store
        .profiles
        .iter_mut()
        .find(|p| p.id == id)
        .ok_or_else(|| "找不到这个账号快照".to_string())?;
    profile.name = clean_name.to_string();
    profile.notes = notes;
    profile.updated_at = Utc::now();
    save_store(&store)
}

#[tauri::command]
fn create_backup() -> Result<BackupResult, String> {
    create_backup_with_label("manual")
}

/// 扫描 backups 目录下的 *.json，解析每个备份的 id/label/created_at，
/// 按 created_at 倒序（最新在前）返回。解析失败的单个文件跳过，不阻断整体列举。
#[tauri::command]
fn list_backups() -> Result<Vec<BackupSummary>, String> {
    ensure_app_dirs()?;
    let dir = backups_dir()?;
    let entries = match fs::read_dir(&dir) {
        Ok(entries) => entries,
        // 目录不存在/读不出来：当成空列表，不报错。
        Err(_) => return Ok(Vec::new()),
    };

    let mut summaries: Vec<BackupSummary> = entries
        .filter_map(|entry| entry.ok())
        .map(|entry| entry.path())
        .filter(|path| {
            path.is_file() && path.extension().and_then(|e| e.to_str()) == Some("json")
        })
        .filter_map(|path| {
            // 文件名（仅用于日志，避免泄露完整路径）。
            let file_name = path
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("<unknown>")
                .to_string();
            // 单个文件读失败：打一行 warn（含文件名）再跳过，不再静默 .ok()? 丢弃。
            let raw = match fs::read_to_string(&path) {
                Ok(raw) => raw,
                Err(e) => {
                    eprintln!("[claude-switcher] list_backups: 跳过坏备份「{file_name}」(读取失败): {e}");
                    return None;
                }
            };
            // 单个文件 JSON 解析失败：同样 warn + 跳过，不污染整列表。
            let value: Value = match serde_json::from_str(&raw) {
                Ok(value) => value,
                Err(e) => {
                    eprintln!("[claude-switcher] list_backups: 跳过坏备份「{file_name}」(JSON 解析失败): {e}");
                    return None;
                }
            };
            // id 优先取文件内字段，缺失就退回文件名（去掉 .json 扩展名）。
            let id = value
                .get("id")
                .and_then(|v| v.as_str())
                .map(ToOwned::to_owned)
                .or_else(|| {
                    path.file_stem()
                        .and_then(|n| n.to_str())
                        .map(ToOwned::to_owned)
                })?;
            let label = value
                .get("label")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            let created_at = value
                .get("created_at")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            Some(BackupSummary {
                id,
                label,
                created_at,
            })
        })
        .collect();

    // 倒序：created_at 是 RFC3339 ISO 字符串，字典序即时间序，倒排即最新在前。
    summaries.sort_by(|a, b| b.created_at.cmp(&a.created_at));
    Ok(summaries)
}

/// H1：从 ~/.claude-switcher/backups/<id>.json 把 claude_json / settings_json /
/// keychain_password 写回磁盘和钥匙串。恢复前自动创建一份 before-restore 备份。
#[tauri::command]
fn restore_backup(id: String) -> Result<RestoreResult, String> {
    let clean_id = id.trim();
    if clean_id.is_empty() {
        return Err("备份 id 不能为空".to_string());
    }
    // 防路径穿越：备份名只允许时间戳/uuid 字符。
    if clean_id.contains('/') || clean_id.contains('\\') || clean_id.contains("..") {
        return Err("非法的备份 id".to_string());
    }

    let path = backups_dir()?.join(format!("{clean_id}.json"));
    if !path.exists() {
        return Err(format!("找不到备份文件: {}", path.to_string_lossy()));
    }
    let raw = fs::read_to_string(&path).map_err(|e| format!("读取备份失败: {e}"))?;
    let backup: Value =
        serde_json::from_str(&raw).map_err(|e| format!("备份 JSON 解析失败: {e}"))?;

    let mut warnings = Vec::new();

    // H2：恢复前 best-effort 检测 Claude Code 是否在运行（非阻断）。
    if claude_code_running() {
        warnings.push(
            "检测到 Claude Code 仍在运行，恢复不会作用于已运行的会话，请恢复后重启 Claude Code"
                .to_string(),
        );
    }

    // 先备份当前状态，避免恢复把现状冲掉后无法回退；这份 before-restore 备份同时作为回滚源。
    let backup_result = create_backup_with_label("before-restore")?;

    let claude_json = backup.get("claude_json").filter(|v| !v.is_null());
    let settings_json = backup.get("settings_json").filter(|v| !v.is_null());
    // C2：备份里的 keychain_password 可能是加密值或旧明文，写进真实 Keychain 前先解密。
    let keychain_password = match backup
        .get("keychain_password")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
    {
        Some(raw) => Some(decrypt_secret(raw)?),
        None => None,
    };

    if claude_json.is_none() && settings_json.is_none() && keychain_password.is_none() {
        return Err("该备份不包含任何可恢复的内容".to_string());
    }

    // FullReplace 语义：缺失的项不是「跳过」而是「删除/清空」，把告警措辞改成回滚语义。
    if claude_json.is_none() {
        warnings.push(
            "备份缺少 claude_json，将删除当前 ~/.claude.json（完整还原到备份时刻）".to_string(),
        );
    }
    if settings_json.is_none() {
        warnings.push(
            "备份缺少 settings_json，将删除当前 ~/.claude/settings.json（完整还原到备份时刻）"
                .to_string(),
        );
    }
    if keychain_password.is_none() {
        warnings.push(
            "备份缺少 keychain_password，将清空当前 Keychain（完整还原到备份时刻）".to_string(),
        );
    }

    // 事务化恢复：用刚创建的 before-restore 备份做回滚源，与 switch_profile 走同一 helper，
    // 任一步写失败都会把账号材料整体还原回恢复前的状态。
    // restore 用 FullReplace：整体覆盖 + 缺失即删除/清空，符合「回滚到备份时刻」语义。
    let rollback_from = load_backup_snapshot(&PathBuf::from(&backup_result.path))?;
    apply_account_material(
        WriteMode::FullReplace,
        claude_json,
        settings_json,
        keychain_password.as_deref(),
        &rollback_from,
    )?;

    // 保持性：FullReplace 可能整体覆盖甚至删除 settings.json（备份缺 settings_json 时），
    // 把隐私 env 冲掉。恢复刚写完/删完 settings 后，立即按 store 当前 telemetry_mode
    // 把隐私 env 合并回去；helper 幂等，settings 不存在时会按需重建（Default 模式不建文件）。
    // 调用时机在 apply_account_material 之后、已过事务回滚保护区；恢复已成功落盘，
    // 隐私 env 注入失败属非关键，best-effort：只记 warning，不让恢复返回 Err。
    let store = load_store()?;
    let runtime = store.current_profile_id.as_deref().and_then(|id| {
        store
            .profiles
            .iter()
            .find(|profile| profile.id == id)
            .and_then(|profile| profile.runtime.clone())
    });
    if let Err(e) = apply_profile_env_to_settings(store.telemetry_mode, runtime.as_ref()) {
        warnings.push(format!(
            "隐私 env 注入失败（可在设置里重选遥测模式重试）：{e}"
        ));
    }

    Ok(RestoreResult {
        restored_from: clean_id.to_string(),
        backup: backup_result,
        warnings,
    })
}

#[tauri::command]
fn open_data_dir() -> Result<(), String> {
    let path = app_data_dir()?;
    let output = Command::new("open")
        .arg(path)
        .output()
        .map_err(|e| format!("打开目录失败: {e}"))?;
    if output.status.success() {
        Ok(())
    } else {
        Err(format!(
            "打开目录失败: {}",
            String::from_utf8_lossy(&output.stderr)
        ))
    }
}

#[tauri::command]
fn inspect_local_files() -> Result<BTreeMap<String, bool>, String> {
    let mut map = BTreeMap::new();
    map.insert("~/.claude.json".to_string(), claude_json_path()?.exists());
    map.insert(
        "~/.claude/settings.json".to_string(),
        claude_settings_path()?.exists(),
    );
    map.insert(
        "~/.claude/.credentials.json".to_string(),
        legacy_credentials_path()?.exists(),
    );
    map.insert(
        "Keychain Claude Code-credentials".to_string(),
        read_keychain_password()?.is_some(),
    );
    map.insert(
        "~/.claude-switcher/store.private.json".to_string(),
        store_path()?.exists(),
    );
    Ok(map)
}

#[tauri::command]
fn show_main_window_cmd(app: AppHandle) {
    show_main_window(&app);
}

pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        .setup(|app| {
            if let Err(error) = install_tray_handlers(app) {
                eprintln!("[claude-switcher] 初始化菜单栏状态失败: {error}");
            }
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            get_status,
            set_telemetry_mode,
            list_profiles,
            capture_current_profile,
            prepare_new_account_login,
            complete_new_account_login,
            switch_profile,
            get_clash_status,
            get_claude_usage,
            switch_clash_node,
            switch_profile_clash_node,
            set_profile_clash_binding,
            set_profile_runtime_binding,
            delete_profile,
            rename_profile,
            create_backup,
            list_backups,
            restore_backup,
            open_data_dir,
            inspect_local_files,
            show_main_window_cmd,
        ])
        .run(tauri::generate_context!())
        .expect("error while running Claude Switcher");
}
