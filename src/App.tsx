import { useCallback, useEffect, useMemo, useState } from 'react';
import { invoke } from '@tauri-apps/api/core';
import { getCurrentWebviewWindow } from '@tauri-apps/api/webviewWindow';
import {
  Archive,
  Activity,
  BarChart3,
  CheckCircle2,
  Clock,
  Database,
  ExternalLink,
  EyeOff,
  FileKey,
  Fingerprint,
  History,
  Loader2,
  Network,
  Plus,
  RefreshCw,
  Router,
  RotateCcw,
  ShieldAlert,
  Trash2,
  UserRound,
} from 'lucide-react';
import { ClaudeTrayPopup } from './components/ClaudeTrayPopup';

const WINDOW_LABEL = (() => {
  if (new URLSearchParams(window.location.search).get('window') === 'tray-popup') {
    return 'tray-popup';
  }
  try {
    return getCurrentWebviewWindow().label;
  } catch {
    return 'main';
  }
})();

interface ProfileMeta {
  email?: string | null;
  account_uuid?: string | null;
  organization_uuid?: string | null;
  organization_name?: string | null;
  user_id_hash?: string | null;
  has_oauth_account: boolean;
  has_keychain_credentials: boolean;
  has_trusted_device_token: boolean;
  subscription_type?: string | null;
  rate_limit_tier?: string | null;
}

interface ProfileSummary {
  id: string;
  name: string;
  notes?: string | null;
  created_at: string;
  updated_at: string;
  last_switched_at?: string | null;
  meta: ProfileMeta;
  clash?: ProfileClashBinding | null;
  is_current: boolean;
}

interface ProfileClashBinding {
  enabled: boolean;
  group: string;
  node: string;
}

interface ClaudeStatus {
  claude_json_exists: boolean;
  settings_json_exists: boolean;
  credentials_json_exists: boolean;
  keychain_exists: boolean;
  keychain_parse_ok: boolean;
  meta: ProfileMeta;
  claude_json_path: string;
  settings_json_path: string;
  data_dir: string;
  backup_dir: string;
  session_isolation: SessionIsolationStatus;
  profile_count: number;
  current_profile_id?: string | null;
  current_profile_name?: string | null;
  pending_new_account?: PendingNewAccount | null;
  warnings: string[];
  telemetry_mode: TelemetryMode;
}

interface SessionIsolationStatus {
  enabled: boolean;
  live_path: string;
  target_path?: string | null;
  current_profile_path?: string | null;
}

interface PendingNewAccount {
  id: string;
  name: string;
  notes?: string | null;
  group: string;
  node: string;
  created_at: string;
}

interface BackupResult {
  id: string;
  path: string;
  created_at: string;
}

interface SwitchResult {
  switched_to: string;
  backup: BackupResult;
  clash?: ClashSwitchResult | null;
  restart_hint: string;
  warnings: string[];
}

interface PrepareNewAccountResult {
  pending: PendingNewAccount;
  backup: BackupResult;
  clash: ClashSwitchResult;
  warnings: string[];
}

interface RestoreResult {
  restored_from: string;
  warnings: string[];
}

interface BackupSummary {
  id: string;
  label: string;
  created_at: string;
}

interface ClashStatus {
  available: boolean;
  controller: string;
  group: string;
  group_type?: string | null;
  now?: string | null;
  nodes: string[];
  error?: string | null;
}

interface ClashSwitchResult {
  group: string;
  node: string;
  previous?: string | null;
  verified: boolean;
}

interface TokenTotals {
  input_tokens: number;
  cache_creation_input_tokens: number;
  cache_read_input_tokens: number;
  output_tokens: number;
  total_tokens: number;
}

interface UsageWindow {
  label: string;
  totals: TokenTotals;
  message_count: number;
  reset_at?: string | null;
  used_percent?: number | null;
}

interface DailyUsage {
  date: string;
  totals: TokenTotals;
  message_count: number;
}

interface ClaudeUsageSnapshot {
  updated_at: string;
  scanned_files: number;
  scanned_messages: number;
  latest_message_at?: string | null;
  session: UsageWindow;
  weekly: UsageWindow;
  today: UsageWindow;
  last_30_days: UsageWindow;
  daily: DailyUsage[];
  top_model?: string | null;
  warnings: string[];
}

type BusyAction =
  | 'refresh'
  | 'capture'
  | 'new-login'
  | 'finish-new'
  | 'switch'
  | 'backup'
  | 'delete'
  | 'bind'
  | 'clash'
  | 'list-backups'
  | 'restore'
  | 'telemetry'
  | null;

// 遥测去关联：三态。后端按这些字符串向 settings.env 注入 / 清理隐私 env。
type TelemetryMode = 'default' | 'disableTelemetry' | 'essentialOnly';

const TELEMETRY_OPTIONS: {
  value: TelemetryMode;
  label: string;
  badge?: string;
  desc: string;
}[] = [
  {
    value: 'default',
    label: '关闭',
    desc: '不注入任何隐私 env，保持 Claude Code 默认行为（遥测照常上报）。',
  },
  {
    value: 'disableTelemetry',
    label: '去关联',
    badge: '推荐',
    desc: '注入 DISABLE_TELEMETRY=1，关闭会把同设备多账号关联起来的遥测（Datadog / 事件 / GrowthBook），副作用极小。',
  },
  {
    value: 'essentialOnly',
    label: '最强',
    desc: '注入 CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC=1，关掉一切非必要流量。',
  },
];

const fmt = new Intl.DateTimeFormat('zh-CN', {
  month: '2-digit',
  day: '2-digit',
  hour: '2-digit',
  minute: '2-digit',
});

function shortId(value?: string | null) {
  if (!value) return '未发现';
  if (value.includes('@')) {
    const [name, domain] = value.split('@');
    return `${name.slice(0, 2)}***@${domain}`;
  }
  return value.length > 14 ? `${value.slice(0, 8)}…${value.slice(-4)}` : value;
}

function statusAccountLabel(status?: ClaudeStatus | null) {
  return status?.meta.email ? shortId(status.meta.email) : status?.current_profile_name || '未发现';
}

function dateLabel(value?: string | null) {
  if (!value) return '从未';
  return fmt.format(new Date(value));
}

function relativeTime(value?: string | null) {
  if (!value) return '无记录';
  const diff = new Date(value).getTime() - Date.now();
  const abs = Math.abs(diff);
  const minutes = Math.round(abs / 60000);
  if (minutes < 1) return diff >= 0 ? '马上' : '刚刚';
  if (minutes < 60) return diff >= 0 ? `${minutes} 分钟后` : `${minutes} 分钟前`;
  const hours = Math.round(minutes / 60);
  if (hours < 24) return diff >= 0 ? `${hours} 小时后` : `${hours} 小时前`;
  const days = Math.round(hours / 24);
  return diff >= 0 ? `${days} 天后` : `${days} 天前`;
}

function compactNumber(value?: number | null) {
  const next = value ?? 0;
  if (next >= 1_000_000_000) return `${(next / 1_000_000_000).toFixed(next >= 10_000_000_000 ? 0 : 1)}B`;
  if (next >= 1_000_000) return `${(next / 1_000_000).toFixed(next >= 10_000_000 ? 0 : 1)}M`;
  if (next >= 1_000) return `${(next / 1_000).toFixed(next >= 10_000 ? 0 : 1)}K`;
  return `${next}`;
}

function usagePercent(window: UsageWindow | undefined, max: number) {
  if (!window || max <= 0) return 0;
  if (typeof window.used_percent === 'number') {
    return Math.max(3, Math.min(100, 100 - window.used_percent));
  }
  return Math.max(3, Math.min(100, (window.totals.total_tokens / max) * 100));
}

function usageLabel(window?: UsageWindow | null) {
  if (typeof window?.used_percent === 'number') {
    return `${Math.round(Math.max(0, Math.min(100, 100 - window.used_percent)))}% 剩余`;
  }
  return `${compactNumber(window?.totals.total_tokens)} token`;
}

function StatusPill({ ok, label }: { ok: boolean; label: string }) {
  return <span className={ok ? 'pill ok' : 'pill muted'}>{label}</span>;
}

function Field({ label, value }: { label: string; value?: string | null }) {
  return (
    <div className="field">
      <span>{label}</span>
      <strong>{value || '未发现'}</strong>
    </div>
  );
}

function StatusIcon({
  ok,
  label,
  detail,
}: {
  ok: boolean;
  label: string;
  detail: string;
}) {
  return (
    <div className={ok ? 'status-icon ok' : 'status-icon warn'}>
      <span>{ok ? <CheckCircle2 /> : <ShieldAlert />}</span>
      <div>
        <strong>{label}</strong>
        <em>{detail}</em>
      </div>
    </div>
  );
}

function UsageRow({ item, max }: { item: UsageWindow; max: number }) {
  return (
    <div className="usage-row">
      <div className="usage-row-head">
        <strong>{item.label}</strong>
        <span>{usageLabel(item)}</span>
      </div>
      <div className="usage-bar">
        <span style={{ width: `${usagePercent(item, max)}%` }} />
      </div>
      <div className="usage-row-foot">
        <span>{compactNumber(item.totals.total_tokens)} token · {item.message_count} 条 usage</span>
        <span>{item.reset_at ? `${relativeTime(item.reset_at)}重置` : '无重置估算'}</span>
      </div>
    </div>
  );
}

function emptyTotals(): TokenTotals {
  return {
    input_tokens: 0,
    cache_creation_input_tokens: 0,
    cache_read_input_tokens: 0,
    output_tokens: 0,
    total_tokens: 0,
  };
}

function fallbackWindow(label: string): UsageWindow {
  return {
    label,
    totals: emptyTotals(),
    message_count: 0,
    reset_at: null,
  };
}

function App() {
  if (WINDOW_LABEL === 'tray-popup') {
    return <ClaudeTrayPopup />;
  }

  const [status, setStatus] = useState<ClaudeStatus | null>(null);
  const [profiles, setProfiles] = useState<ProfileSummary[]>([]);
  const [usage, setUsage] = useState<ClaudeUsageSnapshot | null>(null);
  const [name, setName] = useState('');
  const [notes, setNotes] = useState('');
  const [newAccountName, setNewAccountName] = useState('尼区');
  const [newAccountNotes, setNewAccountNotes] = useState('');
  const [newAccountNode, setNewAccountNode] = useState('');
  const [toast, setToast] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState<BusyAction | null>(null);
  const [clashStatus, setClashStatus] = useState<ClashStatus | null>(null);
  const [actionWarnings, setActionWarnings] = useState<string[]>([]);
  const [backups, setBackups] = useState<BackupSummary[]>([]);
  const [telemetryMode, setTelemetryMode] = useState<TelemetryMode | null>(null);

  const currentProfile = useMemo(
    () => profiles.find((profile) => profile.is_current) || null,
    [profiles],
  );

  useEffect(() => {
    if (newAccountNode || !clashStatus?.nodes.length) return;
    const preferred =
      clashStatus.nodes.find((node) => node === '南非-B') ||
      clashStatus.nodes.find((node) => node.includes('南非')) ||
      '';
    if (preferred) setNewAccountNode(preferred);
  }, [clashStatus?.nodes, newAccountNode]);

  const load = useCallback(async () => {
    setBusy('refresh');
    setError(null);
    try {
      const [nextStatus, nextProfiles, nextBackups] = await Promise.all([
        invoke<ClaudeStatus>('get_status'),
        invoke<ProfileSummary[]>('list_profiles'),
        invoke<BackupSummary[]>('list_backups'),
      ]);
      setStatus(nextStatus);
      setProfiles(nextProfiles);
      setBackups(nextBackups);

      // 遥测模式：get_status 始终带 telemetry_mode（后端非 Option 字段）。
      setTelemetryMode(nextStatus.telemetry_mode);

      Promise.all([
        invoke<ClaudeUsageSnapshot>('get_claude_usage').catch((err) => ({
          updated_at: new Date().toISOString(),
          scanned_files: 0,
          scanned_messages: 0,
          latest_message_at: null,
          session: { label: '近 5 小时', totals: emptyTotals(), message_count: 0, reset_at: null },
          weekly: { label: '近 7 天', totals: emptyTotals(), message_count: 0, reset_at: null },
          today: { label: '今天', totals: emptyTotals(), message_count: 0, reset_at: null },
          last_30_days: { label: '近 30 天', totals: emptyTotals(), message_count: 0, reset_at: null },
          daily: [],
          top_model: null,
          warnings: [String(err)],
        })),
        invoke<ClashStatus>('get_clash_status').catch((err) => ({
          available: false,
          controller: 'http://127.0.0.1:9090',
          group: 'Auto-Claude',
          nodes: [],
          error: String(err),
        })),
      ]).then(([nextUsage, nextClashStatus]) => {
        setUsage(nextUsage);
        setClashStatus(nextClashStatus);
      });
    } catch (err) {
      setError(String(err));
    } finally {
      setBusy(null);
    }
  }, []);

  useEffect(() => {
    load();
  }, [load]);

  const run = async (action: BusyAction, fn: () => Promise<string | void>) => {
    setBusy(action);
    setError(null);
    try {
      const message = await fn();
      if (message) setToast(message);
      await load();
    } catch (err) {
      setError(String(err));
    } finally {
      setBusy(null);
    }
  };

  const capture = () =>
    run('capture', async () => {
      await invoke('capture_current_profile', {
        name: name.trim(),
        notes: notes.trim() || null,
      });
      setName('');
      setNotes('');
      return '已保存当前 Claude Code 账号快照';
    });

  const prepareNewAccount = () => {
    if (
      !window.confirm(
        `准备新号登录「${newAccountName.trim()}」？\n\n工具会先结束所有 Claude Code CLI 进程，保存当前账号状态，把 Auto-Claude 切到「${newAccountNode}」，清空当前 Claude OAuth，并打开一个干净的 Claude 登录窗口。`,
      )
    )
      return;
    run('new-login', async () => {
      setActionWarnings([]);
      const result = await invoke<PrepareNewAccountResult>('prepare_new_account_login', {
        name: newAccountName.trim(),
        notes: newAccountNotes.trim() || null,
        node: newAccountNode,
      });
      setActionWarnings(result.warnings ?? []);
      return `已准备新号「${result.pending.name}」登录；Auto-Claude 已切到 ${result.clash.node}`;
    });
  };

  const finishNewAccount = () =>
    run('finish-new', async () => {
      await invoke<ProfileSummary>('complete_new_account_login');
      setNewAccountName('尼区');
      setNewAccountNotes('');
      setNewAccountNode('');
      return '新号已保存并绑定节点';
    });

  const switchTo = (id: string) =>
    run('switch', async () => {
      setActionWarnings([]);
      const result = await invoke<SwitchResult>('switch_profile', { id });
      setActionWarnings(result.warnings ?? []);
      const clash = result.clash
        ? `Auto-Claude 已切到 ${result.clash.node}；`
        : '';
      return `${result.switched_to} 已切换；${clash}${result.restart_hint}`;
    });

  const loadBackups = useCallback(async () => {
    const next = await invoke<BackupSummary[]>('list_backups');
    setBackups(next);
  }, []);

  const refreshBackups = () =>
    run('list-backups', async () => {
      await loadBackups();
    });

  const backup = () =>
    run('backup', async () => {
      const result = await invoke<BackupResult>('create_backup');
      await loadBackups().catch(() => undefined);
      return `备份已写入 ${result.path}`;
    });

  const restore = (id: string, label: string) => {
    if (
      !window.confirm(
        `完整还原到备份「${label}」？\n\n会用该备份覆盖当前 ~/.claude.json、settings.json 和钥匙串登录态；备份中缺失的项会被删除 / 清空。\n还原前会自动创建一次 before-restore 备份以便回滚。`,
      )
    )
      return;
    run('restore', async () => {
      setActionWarnings([]);
      const result = await invoke<RestoreResult>('restore_backup', { id });
      setActionWarnings(result.warnings ?? []);
      return `已从 ${result.restored_from} 恢复`;
    });
  };

  const remove = (id: string, label: string) => {
    if (!window.confirm(`删除账号快照「${label}」？这不会删除 Claude Code 当前登录。`)) return;
    run('delete', async () => {
      await invoke('delete_profile', { id });
      return '账号快照已删除';
    });
  };

  const bindNode = (id: string, node: string) =>
    run('bind', async () => {
      await invoke('set_profile_clash_binding', {
        id,
        enabled: node.length > 0,
        group: 'Auto-Claude',
        node,
      });
      return node ? `已绑定 Auto-Claude -> ${node}` : '已清除这个账号的节点绑定';
    });

  const testProfileNode = (id: string) =>
    run('clash', async () => {
      const result = await invoke<ClashSwitchResult>('switch_profile_clash_node', { id });
      return result.verified
        ? `Auto-Claude 已切到 ${result.node}`
        : `已请求切到 ${result.node}，但 Clash 当前状态未确认`;
    });

  const openDataDir = () =>
    run(null, async () => {
      await invoke('open_data_dir');
    });

  const applyTelemetryMode = (mode: TelemetryMode) => {
    if (mode === telemetryMode) return;
    run('telemetry', async () => {
      await invoke('set_telemetry_mode', { mode });
      const label = TELEMETRY_OPTIONS.find((o) => o.value === mode)?.label ?? mode;
      return `遥测去关联已切到「${label}」`;
    });
  };

  const canCapture = name.trim().length > 0 && !busy;
  const canPrepareNewAccount =
    newAccountName.trim().length > 0 && newAccountNode.length > 0 && !busy && !status?.pending_new_account;
  const canFinishNewAccount = !!status?.pending_new_account && !busy;
  const usageMax = Math.max(
    usage?.session.totals.total_tokens ?? 0,
    usage?.weekly.totals.total_tokens ?? 0,
    usage?.today.totals.total_tokens ?? 0,
    usage?.last_30_days.totals.total_tokens ?? 0,
    1,
  );
  const dailyMax = Math.max(...(usage?.daily ?? []).map((item) => item.totals.total_tokens), 1);

  return (
    <main className="app">
      <section className="header">
        <div>
          <div className="eyebrow">Claude Code Local Account Switcher</div>
          <h1>账号快照控制台</h1>
        </div>
        <div className="header-actions">
          <button className="ghost" onClick={() => load()} disabled={!!busy}>
            {busy === 'refresh' ? <Loader2 className="spin" /> : <RefreshCw />}
            刷新
          </button>
          <button className="ghost" onClick={backup} disabled={!!busy}>
            <Archive />
            手动备份
          </button>
        </div>
      </section>

      {(error || toast) && (
        <div className={error ? 'notice error' : 'notice'}>
          {error ? <ShieldAlert /> : <CheckCircle2 />}
          <span>{error || toast}</span>
          <button onClick={() => (error ? setError(null) : setToast(null))}>关闭</button>
        </div>
      )}

      {actionWarnings.length > 0 && (
        <div className="notice error">
          <ShieldAlert />
          <div className="warnings" style={{ marginTop: 0 }}>
            {actionWarnings.map((warning) => (
              <div key={warning}>
                <ShieldAlert />
                {warning}
              </div>
            ))}
          </div>
          <button onClick={() => setActionWarnings([])}>关闭</button>
        </div>
      )}

      <section className="grid">
        <div className="panel current-panel">
          <div className="panel-title">
            <UserRound />
            <span>当前本机状态</span>
          </div>
          <div className="identity">
            <strong>{statusAccountLabel(status)}</strong>
            <span>{status?.meta.organization_name || '未读取到组织名'}</span>
          </div>
          <div className="pills">
            <StatusPill ok={!!status?.claude_json_exists} label="~/.claude.json" />
            <StatusPill ok={!!status?.keychain_exists} label="Keychain" />
            <StatusPill ok={!!status?.keychain_parse_ok} label="凭据 JSON" />
            <StatusPill ok={!!status?.settings_json_exists} label="settings.json" />
          </div>
          <div className="fields two">
            <Field label="账号 UUID" value={shortId(status?.meta.account_uuid)} />
            <Field label="组织 UUID" value={shortId(status?.meta.organization_uuid)} />
            <Field label="Device ID 哈希" value={status?.meta.user_id_hash} />
            <Field label="订阅" value={status?.meta.subscription_type} />
            <Field label="限额层级" value={status?.meta.rate_limit_tier} />
          </div>
          {!!status?.warnings.length && (
            <div className="warnings">
              {status.warnings.map((warning) => (
                <div key={warning}>
                  <ShieldAlert />
                  {warning}
                </div>
              ))}
            </div>
          )}
          <div className="status-icons">
            <StatusIcon
              ok={!!status?.meta.has_oauth_account}
              label="账号"
              detail={statusAccountLabel(status)}
            />
            <StatusIcon
              ok={!!status?.keychain_exists && !!status?.keychain_parse_ok}
              label="Keychain"
              detail={status?.keychain_exists ? 'OAuth 已保存' : '未发现'}
            />
            <StatusIcon
              ok={!!clashStatus?.available}
              label="Auto-Claude"
              detail={clashStatus?.now || '未连接'}
            />
            <StatusIcon
              ok={typeof usage?.session.used_percent === 'number' || !!usage?.scanned_messages}
              label="额度"
              detail={usage ? usageLabel(usage.session) : '读取中'}
            />
          </div>
        </div>

        <div className="panel capture-panel">
          <div className="panel-title">
            <Plus />
            <span>保存当前账号</span>
          </div>
          <label>
            名称
            <input
              value={name}
              onChange={(event) => setName(event.target.value)}
              placeholder="例如 Claude 主号 / Claude 备用号"
            />
          </label>
          <label>
            备注
            <textarea
              value={notes}
              onChange={(event) => setNotes(event.target.value)}
              placeholder="用途、套餐、来源，留空也可以"
              rows={4}
            />
          </label>
          <button className="primary" onClick={capture} disabled={!canCapture}>
            {busy === 'capture' ? <Loader2 className="spin" /> : <FileKey />}
            保存快照
          </button>
        </div>

        <div className="panel onboarding-panel">
          <div className="panel-title">
            <UserRound />
            <span>一键新号</span>
          </div>
          {status?.pending_new_account ? (
            <div className="pending-account">
              <div>
                <span>待完成</span>
                <strong>{status.pending_new_account.name}</strong>
              </div>
              <div>
                <span>节点</span>
                <strong>{status.pending_new_account.node}</strong>
              </div>
              <p>在刚打开的 Claude 窗口完成 OAuth 登录后，点下面保存成正式账号。</p>
              <button className="primary wide" onClick={finishNewAccount} disabled={!canFinishNewAccount}>
                {busy === 'finish-new' ? <Loader2 className="spin" /> : <CheckCircle2 />}
                登录完成后保存
              </button>
            </div>
          ) : (
            <>
              <label>
                新号名称
                <input
                  value={newAccountName}
                  onChange={(event) => setNewAccountName(event.target.value)}
                  placeholder="例如 尼区 / Claude 备用号"
                />
              </label>
              <label>
                绑定节点
                <select
                  value={newAccountNode}
                  onChange={(event) => setNewAccountNode(event.target.value)}
                  disabled={!!busy || !clashStatus?.nodes.length}
                >
                  <option value="">选择新号节点</option>
                  {clashStatus?.nodes.map((node) => (
                    <option key={node} value={node}>
                      {node}
                    </option>
                  ))}
                </select>
              </label>
              <label>
                备注
                <textarea
                  value={newAccountNotes}
                  onChange={(event) => setNewAccountNotes(event.target.value)}
                  placeholder="套餐、地区、用途，留空也可以"
                  rows={3}
                />
              </label>
              <button className="primary wide" onClick={prepareNewAccount} disabled={!canPrepareNewAccount}>
                {busy === 'new-login' ? <Loader2 className="spin" /> : <ShieldAlert />}
                准备并打开登录
              </button>
            </>
          )}
        </div>

        <div className="panel network-panel">
          <div className="panel-title">
            <Network />
            <span>网络节点</span>
          </div>
          <div className="clash-summary">
            <div>
              <span>控制器</span>
              <strong>{clashStatus?.controller || '未连接'}</strong>
            </div>
            <div>
              <span>组</span>
              <strong>{clashStatus?.group || 'Auto-Claude'}</strong>
            </div>
            <div>
              <span>当前节点</span>
              <strong>{clashStatus?.now || '未读取'}</strong>
            </div>
            <div>
              <span>组类型</span>
              <strong>{clashStatus?.group_type || '未知'}</strong>
            </div>
          </div>
          {clashStatus?.error && <div className="inline-error">{clashStatus.error}</div>}
          {clashStatus?.group_type && clashStatus.group_type !== 'Selector' && (
            <div className="inline-warning">Auto-Claude 不是 select 组，固定账号节点可能被自动测速覆盖。</div>
          )}
          <button className="ghost wide" onClick={() => load()} disabled={!!busy}>
            <RefreshCw />
            刷新 Clash 状态
          </button>
        </div>

        <div className="panel usage-panel">
          <div className="panel-title">
            <BarChart3 />
            <span>Claude 用量</span>
          </div>
          <div className="usage-hero">
            <div>
              <span>更新于 {relativeTime(usage?.updated_at)}</span>
              <strong>{usage ? usageLabel(usage.session) : '读取中'}</strong>
            </div>
            <button className="usage-refresh" onClick={() => load()} disabled={!!busy} title="刷新 Claude 用量">
              {busy === 'refresh' ? <Loader2 className="spin" /> : <RefreshCw />}
            </button>
          </div>
          <div className="usage-grid">
            <UsageRow item={usage?.session ?? fallbackWindow('近 5 小时')} max={usageMax} />
            <UsageRow item={usage?.weekly ?? fallbackWindow('近 7 天')} max={usageMax} />
          </div>
          <div className="usage-stats">
            <div>
              <span>今天</span>
              <strong>{compactNumber(usage?.today.totals.total_tokens)}</strong>
            </div>
            <div>
              <span>近 30 天</span>
              <strong>{compactNumber(usage?.last_30_days.totals.total_tokens)}</strong>
            </div>
            <div>
              <span>常用模型</span>
              <strong>{usage?.top_model || '暂无'}</strong>
            </div>
            <div>
              <span>日志</span>
              <strong>{usage?.scanned_files ?? 0} 文件</strong>
            </div>
          </div>
          <div className="daily-bars" aria-label="近 30 天 token 用量">
            {(usage?.daily ?? []).map((item) => (
              <span
                key={item.date}
                title={`${item.date} · ${compactNumber(item.totals.total_tokens)} token`}
                style={{
                  height: `${Math.max(4, (item.totals.total_tokens / dailyMax) * 76)}px`,
                }}
              />
            ))}
          </div>
          <p className="usage-note">
            额度百分比来自官方 Claude OAuth API；token 和柱状图来自本地日志，用于判断消耗趋势。
          </p>
          {!!usage?.warnings.length && (
            <div className="warnings compact">
              {usage.warnings.map((warning) => (
                <div key={warning}>
                  <Activity />
                  {warning}
                </div>
              ))}
            </div>
          )}
        </div>

        <div className="panel files-panel">
          <div className="panel-title">
            <Database />
            <span>数据位置</span>
          </div>
          <div className="path-list">
            <code>{status?.claude_json_path}</code>
            <code>{status?.settings_json_path}</code>
            <code>{status?.data_dir}</code>
          </div>
          <button className="ghost wide" onClick={openDataDir} disabled={!!busy}>
            <ExternalLink />
            打开本工具数据目录
          </button>
        </div>
      </section>

      <section className="profiles">
        <div className="section-title">
          <h2>账号快照</h2>
          <span>{profiles.length} 个</span>
        </div>
        {profiles.length === 0 ? (
          <div className="empty">
            <Fingerprint />
            <strong>还没有保存账号快照</strong>
            <span>先登录一个 Claude Code 账号，然后在上方保存当前账号。</span>
          </div>
        ) : (
          <div className="profile-grid">
            {profiles.map((profile) => (
              <article className={profile.is_current ? 'profile active' : 'profile'} key={profile.id}>
                <div className="profile-head">
                  <div>
                    <strong>{profile.name}</strong>
                    <span>{shortId(profile.meta.email)}</span>
                  </div>
                  {profile.is_current && <span className="active-mark">当前</span>}
                </div>
                <div className="mini-fields">
                  <span>
                    <Fingerprint />
                    Device {profile.meta.user_id_hash || '无'}
                  </span>
                  <span>
                    <Clock />
                    {dateLabel(profile.last_switched_at)}
                  </span>
                  <span>
                    <Router />
                    {profile.clash?.enabled ? profile.clash.node : '节点未绑定'}
                  </span>
                </div>
                <div className="node-bind">
                  <select
                    value={profile.clash?.enabled ? profile.clash.node : ''}
                    onChange={(event) => bindNode(profile.id, event.target.value)}
                    disabled={!!busy || !clashStatus?.nodes.length}
                  >
                    <option value="">不自动切节点</option>
                    {clashStatus?.nodes.map((node) => (
                      <option key={node} value={node}>
                        {node}
                      </option>
                    ))}
                  </select>
                  <button
                    className="ghost"
                    onClick={() => testProfileNode(profile.id)}
                    disabled={!!busy || !profile.clash?.enabled}
                  >
                    测节点
                  </button>
                </div>
                {profile.notes && <p>{profile.notes}</p>}
                <div className="profile-actions">
                  <button
                    className="primary"
                    onClick={() => switchTo(profile.id)}
                    disabled={!!busy || currentProfile?.id === profile.id}
                  >
                    {busy === 'switch' ? <Loader2 className="spin" /> : <CheckCircle2 />}
                    切换
                  </button>
                  <button className="danger" onClick={() => remove(profile.id, profile.name)} disabled={!!busy}>
                    <Trash2 />
                  </button>
                </div>
              </article>
            ))}
          </div>
        )}
      </section>

      <section className="profiles">
        <div className="section-title">
          <h2>遥测去关联</h2>
          <span>
            {TELEMETRY_OPTIONS.find((o) => o.value === telemetryMode)?.label ?? '读取中'}
          </span>
        </div>
        <div className="panel telemetry-panel">
          <div className="panel-title">
            <EyeOff />
            <span>隐私环境变量注入</span>
          </div>
          <p className="telemetry-intro">
            统一写入 ~/.claude/settings.json 的 env；三档隐私 env 互斥，切换时只动这两个 key，不影响 settings 里其它字段。
          </p>
          <div className="telemetry-options">
            {TELEMETRY_OPTIONS.map((option) => {
              const selected = telemetryMode === option.value;
              return (
                <button
                  key={option.value}
                  className={selected ? 'primary' : 'ghost'}
                  onClick={() => applyTelemetryMode(option.value)}
                  disabled={!!busy || telemetryMode === null}
                >
                  {busy === 'telemetry' && selected ? (
                    <Loader2 className="spin" />
                  ) : selected ? (
                    <CheckCircle2 />
                  ) : null}
                  {option.label}
                  {option.badge && <span className="telemetry-badge">{option.badge}</span>}
                </button>
              );
            })}
          </div>
          <div className="telemetry-desc">
            {TELEMETRY_OPTIONS.map((option) => (
              <p
                key={option.value}
                className={telemetryMode === option.value ? 'active' : ''}
              >
                <strong>{option.label}</strong>
                {option.desc}
              </p>
            ))}
          </div>
          {telemetryMode === 'essentialOnly' && (
            <div className="inline-error">
              最强档还会关掉 auto-update / 新模型能力拉取 / trusted-device（手机 bridge）注册——需手动更新 Claude Code。
            </div>
          )}
        </div>
      </section>

      <section className="profiles">
        <div className="section-title">
          <h2>备份与恢复</h2>
          <button className="ghost" onClick={refreshBackups} disabled={!!busy}>
            {busy === 'list-backups' ? <Loader2 className="spin" /> : <History />}
            刷新备份列表
          </button>
        </div>
        {backups.length === 0 ? (
          <div className="empty">
            <History />
            <strong>还没有备份</strong>
            <span>切换账号或点击「手动备份」后会在这里出现。</span>
          </div>
        ) : (
          <div className="profile-grid">
            {backups.map((item) => (
              <article className="profile" key={item.id}>
                <div className="profile-head">
                  <div>
                    <strong>{item.label}</strong>
                    <span>{dateLabel(item.created_at)}</span>
                  </div>
                </div>
                <div className="mini-fields">
                  <span>
                    <Clock />
                    {dateLabel(item.created_at)}
                  </span>
                  <span>
                    <FileKey />
                    {item.id}
                  </span>
                </div>
                <div className="profile-actions">
                  <button
                    className="primary"
                    onClick={() => restore(item.id, item.label)}
                    disabled={!!busy}
                  >
                    {busy === 'restore' ? <Loader2 className="spin" /> : <RotateCcw />}
                    恢复
                  </button>
                </div>
              </article>
            ))}
          </div>
        )}
      </section>
    </main>
  );
}

export default App;
