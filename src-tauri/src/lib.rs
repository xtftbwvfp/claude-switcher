use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fs;
use std::path::PathBuf;
use std::process::Command;
use uuid::Uuid;

const KEYCHAIN_SERVICE: &str = "Claude Code-credentials";
const DEFAULT_CLASH_GROUP: &str = "Auto-Claude";
const AUTH_ENV_KEYS: &[&str] = &[
    "ANTHROPIC_API_KEY",
    "ANTHROPIC_AUTH_TOKEN",
    "CLAUDE_CODE_OAUTH_TOKEN",
    "CLAUDE_CODE_API_KEY_HELPER",
];

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
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ProfileClashBinding {
    enabled: bool,
    group: String,
    node: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct ProfileMeta {
    email: Option<String>,
    account_uuid: Option<String>,
    organization_uuid: Option<String>,
    organization_name: Option<String>,
    user_id_hash: Option<String>,
    credential_hash: Option<String>,
    has_oauth_account: bool,
    has_keychain_credentials: bool,
    has_trusted_device_token: bool,
    subscription_type: Option<String>,
    rate_limit_tier: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct Store {
    profiles: Vec<StoredProfile>,
    current_profile_id: Option<String>,
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
    profile_count: usize,
    current_profile_id: Option<String>,
    warnings: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
struct BackupResult {
    id: String,
    path: String,
    created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize)]
struct SwitchResult {
    switched_to: String,
    backup: BackupResult,
    clash: Option<ClashSwitchResult>,
    restart_hint: String,
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

#[derive(Debug, Clone)]
struct ClashRuntimeConfig {
    controller: String,
    secret: Option<String>,
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
    serde_json::from_str(&raw).map_err(|e| format!("store.private.json 解析失败: {e}"))
}

fn save_store(store: &Store) -> Result<(), String> {
    ensure_app_dirs()?;
    let path = store_path()?;
    let raw = serde_json::to_string_pretty(store).map_err(|e| e.to_string())?;
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
        meta.credential_hash = Some(hash_short(raw));
        if let Ok(parsed) = serde_json::from_str::<Value>(raw) {
            let oauth = parsed.get("claudeAiOauth").unwrap_or(&parsed);
            meta.has_trusted_device_token = oauth.get("trustedDeviceToken").is_some();
            meta.subscription_type =
                string_field(oauth, &["subscriptionType"]).map(ToOwned::to_owned);
            meta.rate_limit_tier = string_field(oauth, &["rateLimitTier"]).map(ToOwned::to_owned);
        }
    }

    meta
}

fn current_username() -> String {
    std::env::var("USER").unwrap_or_else(|_| {
        Command::new("whoami")
            .output()
            .ok()
            .and_then(|output| {
                if output.status.success() {
                    Some(String::from_utf8_lossy(&output.stdout).trim().to_string())
                } else {
                    None
                }
            })
            .filter(|name| !name.is_empty())
            .unwrap_or_else(|| "xiaojian".to_string())
    })
}

fn hex_encode(input: &str) -> String {
    input
        .as_bytes()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>()
}

fn read_keychain_password() -> Result<Option<String>, String> {
    let username = current_username();
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
        let text = String::from_utf8_lossy(&output.stdout).trim_end().to_string();
        return Ok(Some(text));
    }

    // Migration fallback for early claude-switcher builds that wrote the
    // service without Claude Code's account attribute.
    let fallback = Command::new("security")
        .args(["find-generic-password", "-s", KEYCHAIN_SERVICE, "-w"])
        .output()
        .map_err(|e| format!("读取 Keychain 失败: {e}"))?;
    if fallback.status.success() {
        let text = String::from_utf8_lossy(&fallback.stdout).trim_end().to_string();
        return Ok(Some(text));
    }

    let stderr = String::from_utf8_lossy(&output.stderr);
    if stderr.contains("could not be found") || stderr.contains("The specified item could not be found") {
        return Ok(None);
    }
    Ok(None)
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
        return ClashRuntimeConfig { controller, secret };
    }

    ClashRuntimeConfig {
        controller: "http://127.0.0.1:9090".to_string(),
        secret: None,
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

    clash_api("PUT", &clash_group_path(group), Some(json!({ "name": node })))?;
    let after = read_clash_group(group)?;
    let now = string_field(&after, &["now"]).map(ToOwned::to_owned);
    Ok(ClashSwitchResult {
        group: group.to_string(),
        node: node.to_string(),
        previous,
        verified: now.as_deref() == Some(node),
    })
}

fn write_keychain_password(password: &str) -> Result<(), String> {
    let username = current_username();
    loop {
        let output = Command::new("security")
            .args(["delete-generic-password", "-s", KEYCHAIN_SERVICE])
            .output()
            .map_err(|e| format!("清理旧 Keychain 失败: {e}"))?;
        if !output.status.success() {
            break;
        }
    }

    let output = Command::new("security")
        .arg("add-generic-password")
        .arg("-U")
        .arg("-a")
        .arg(username)
        .arg("-s")
        .arg(KEYCHAIN_SERVICE)
        .arg("-X")
        .arg(hex_encode(password))
        .output()
        .map_err(|e| format!("写入 Keychain 失败: {e}"))?;

    if output.status.success() {
        Ok(())
    } else {
        Err(format!(
            "写入 Keychain 失败: {}",
            String::from_utf8_lossy(&output.stderr)
        ))
    }
}

fn current_snapshot() -> Result<(Option<Value>, Option<Value>, Option<String>), String> {
    let claude_json = read_json_optional(claude_json_path()?)?;
    let settings_json = read_json_optional(claude_settings_path()?)?;
    let keychain = read_keychain_password()?;
    Ok((claude_json, settings_json, keychain))
}

fn update_profile_from_snapshot(
    profile: &mut StoredProfile,
    claude_json: Option<Value>,
    settings_json: Option<Value>,
    keychain_password: Option<String>,
) -> Result<(), String> {
    let claude_json =
        claude_json.ok_or_else(|| "当前没有 ~/.claude.json，无法回写当前账号快照".to_string())?;
    if keychain_password.is_none() {
        return Err("当前没有 Keychain Claude Code-credentials，无法回写当前账号快照".to_string());
    }

    profile.meta = extract_meta(Some(&claude_json), keychain_password.as_deref());
    profile.claude_json = claude_json;
    profile.settings_json = settings_json;
    profile.keychain_password = keychain_password;
    profile.updated_at = Utc::now();
    Ok(())
}

fn refresh_current_profile_snapshot(store: &mut Store, target_id: &str) -> Result<(), String> {
    let Some(current_id) = store.current_profile_id.clone() else {
        return Ok(());
    };
    if current_id == target_id {
        return Ok(());
    }
    let Some(profile) = store.profiles.iter_mut().find(|p| p.id == current_id) else {
        return Ok(());
    };
    let (claude_json, settings_json, keychain_password) = current_snapshot()?;
    update_profile_from_snapshot(profile, claude_json, settings_json, keychain_password)
}

fn create_backup_with_label(label: &str) -> Result<BackupResult, String> {
    ensure_app_dirs()?;
    let (claude_json, settings_json, keychain_password) = current_snapshot()?;
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
    Ok(BackupResult {
        id,
        path: path.to_string_lossy().to_string(),
        created_at: Utc::now(),
    })
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
    let meta = extract_meta(claude_json.as_ref(), keychain.as_deref());
    let mut warnings = Vec::new();

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
        profile_count: store.profiles.len(),
        current_profile_id: store.current_profile_id,
        warnings,
    })
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
        is_current: false,
    };
    store.current_profile_id = Some(profile.id.clone());
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
    let backup = create_backup_with_label(&format!("before-switch-to-{id}"))?;
    refresh_current_profile_snapshot(&mut store, &id)?;
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

    let current_claude_json = read_json_optional(claude_json_path()?)?;
    let next_claude_json = merge_claude_json(current_claude_json, &profile.claude_json);
    write_json_pretty(claude_json_path()?, &next_claude_json)?;

    if let Some(settings) = &profile.settings_json {
        write_json_pretty(claude_settings_path()?, settings)?;
    }
    if let Some(password) = &profile.keychain_password {
        write_keychain_password(password)?;
    }

    store.current_profile_id = Some(profile.id.clone());
    store.profiles[idx].last_switched_at = Some(Utc::now());
    store.profiles[idx].updated_at = Utc::now();
    save_store(&store)?;

    Ok(SwitchResult {
        switched_to: profile.name,
        backup,
        clash: clash_result,
        restart_hint: "切换已写入磁盘和 Keychain；请重启正在运行的 Claude Code 会话。".to_string(),
    })
}

#[tauri::command]
fn get_clash_status() -> Result<ClashStatus, String> {
    Ok(clash_status_for_group(DEFAULT_CLASH_GROUP))
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
    map.insert("~/.claude/settings.json".to_string(), claude_settings_path()?.exists());
    map.insert(
        "~/.claude/.credentials.json".to_string(),
        legacy_credentials_path()?.exists(),
    );
    map.insert("Keychain Claude Code-credentials".to_string(), read_keychain_password()?.is_some());
    map.insert("~/.claude-switcher/store.private.json".to_string(), store_path()?.exists());
    Ok(map)
}

pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        .invoke_handler(tauri::generate_handler![
            get_status,
            list_profiles,
            capture_current_profile,
            switch_profile,
            get_clash_status,
            switch_clash_node,
            switch_profile_clash_node,
            set_profile_clash_binding,
            delete_profile,
            rename_profile,
            create_backup,
            open_data_dir,
            inspect_local_files,
        ])
        .run(tauri::generate_context!())
        .expect("error while running Claude Switcher");
}
