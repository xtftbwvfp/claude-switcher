import { useCallback, useEffect, useMemo, useState } from 'react';
import { invoke } from '@tauri-apps/api/core';
import { getCurrentWebviewWindow } from '@tauri-apps/api/webviewWindow';
import './ClaudeTrayPopup.css';

interface ProfileMeta {
  email?: string | null;
  subscription_type?: string | null;
  rate_limit_tier?: string | null;
}

interface ClaudeStatus {
  keychain_exists: boolean;
  keychain_parse_ok: boolean;
  current_profile_name?: string | null;
  meta: ProfileMeta;
}

interface ClashStatus {
  available: boolean;
  now?: string | null;
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

interface ClaudeUsageSnapshot {
  updated_at: string;
  scanned_files: number;
  scanned_messages: number;
  latest_message_at?: string | null;
  session: UsageWindow;
  weekly: UsageWindow;
  today: UsageWindow;
  last_30_days: UsageWindow;
  top_model?: string | null;
}

interface TrayData {
  status: ClaudeStatus | null;
  clash: ClashStatus | null;
  usage: ClaudeUsageSnapshot | null;
}

const PLAN_CAPACITY = {
  standard: {
    session: 250_000_000,
    weekly: 1_000_000_000,
  },
  max: {
    session: 1_000_000_000,
    weekly: 5_000_000_000,
  },
};

function compactNumber(value?: number | null) {
  const next = value ?? 0;
  if (next >= 1_000_000_000) return `${(next / 1_000_000_000).toFixed(next >= 10_000_000_000 ? 0 : 1)}B`;
  if (next >= 1_000_000) return `${(next / 1_000_000).toFixed(next >= 10_000_000 ? 0 : 1)}M`;
  if (next >= 1_000) return `${(next / 1_000).toFixed(next >= 10_000 ? 0 : 1)}K`;
  return `${next}`;
}

function displayedTokens(totals?: TokenTotals | null) {
  if (!totals) return 0;
  return totals.total_tokens ?? 0;
}

function formatCountdown(value?: string | null) {
  if (!value) return '未知';
  const diff = new Date(value).getTime() - Date.now();
  if (diff <= 0) return '已重置';
  const minutes = Math.floor(diff / 60000);
  const hours = Math.floor(minutes / 60);
  const rest = minutes % 60;
  return hours > 0 ? `${hours}h ${rest}m` : `${rest}m`;
}

function shortEmail(value?: string | null) {
  if (!value) return '未读取账号';
  const [name, domain] = value.split('@');
  if (!domain) return value;
  return `${name.slice(0, 3)}***@${domain}`;
}

function accountLabel(status: ClaudeStatus | null) {
  if (status?.meta.email) return shortEmail(status.meta.email);
  return status?.current_profile_name || '未读取账号';
}

function planLabel(status: ClaudeStatus | null) {
  return status?.meta.subscription_type || status?.meta.rate_limit_tier || 'Claude';
}

function capacities(status: ClaudeStatus | null) {
  const label = `${status?.meta.subscription_type ?? ''} ${status?.meta.rate_limit_tier ?? ''}`;
  return /max|team|enterprise/i.test(label) ? PLAN_CAPACITY.max : PLAN_CAPACITY.standard;
}

function remainingPercent(window: UsageWindow | undefined, capacity: number) {
  if (typeof window?.used_percent === 'number') {
    return Math.max(0, Math.min(100, Math.round(100 - window.used_percent)));
  }
  if (!window || capacity <= 0) return 100;
  const used = Math.min(100, (window.totals.total_tokens / capacity) * 100);
  return Math.max(0, Math.round(100 - used));
}

function statusClass(percent: number) {
  if (percent > 50) return 'healthy';
  if (percent > 10) return 'warning';
  return 'critical';
}

function statusLabel(percent: number) {
  if (percent > 50) return 'HEALTHY';
  if (percent > 10) return 'WARNING';
  return 'CRITICAL';
}

function QuotaCard({
  icon,
  title,
  percent,
  resetAt,
}: {
  icon: string;
  title: string;
  percent: number;
  resetAt?: string | null;
}) {
  const level = statusClass(percent);
  return (
    <div className={`ctp-card ${level}`}>
      <div className="ctp-card-header">
        <span className="ctp-card-icon">{icon}</span>
        <span>{title}</span>
        <span className={`ctp-status ${level}`}>{statusLabel(percent)}</span>
      </div>
      <div className="ctp-card-value">
        {percent}
        <span className="ctp-unit">%</span>
        <span className="ctp-remaining">Remaining</span>
      </div>
      <div className="ctp-progress">
        <div className={`ctp-progress-bar ${level}`} style={{ width: `${percent}%` }} />
      </div>
      <div className="ctp-reset">Resets in {formatCountdown(resetAt)}</div>
    </div>
  );
}

export function ClaudeTrayPopup() {
  const [data, setData] = useState<TrayData>({ status: null, clash: null, usage: null });
  const [loading, setLoading] = useState(false);

  const fetchData = useCallback(async () => {
    setLoading(true);
    try {
      const [status, clash, usage] = await Promise.all([
        invoke<ClaudeStatus>('get_status'),
        invoke<ClashStatus>('get_clash_status').catch(() => null),
        invoke<ClaudeUsageSnapshot>('get_claude_usage').catch(() => null),
      ]);
      setData({ status, clash, usage });
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    document.documentElement.classList.add('is-claude-tray-popup');
    document.body.classList.add('is-claude-tray-popup');
    fetchData();
    const interval = window.setInterval(fetchData, 30000);
    return () => {
      window.clearInterval(interval);
      document.documentElement.classList.remove('is-claude-tray-popup');
      document.body.classList.remove('is-claude-tray-popup');
    };
  }, [fetchData]);

  const cap = useMemo(() => capacities(data.status), [data.status]);
  const sessionLeft = remainingPercent(data.usage?.session, cap.session);
  const weeklyLeft = remainingPercent(data.usage?.weekly, cap.weekly);
  const sessionTokens = displayedTokens(data.usage?.session.totals);
  const todayTokens = displayedTokens(data.usage?.today.totals);
  const proxyOn = !!data.clash?.available;
  const keychainOk = !!data.status?.keychain_exists && !!data.status?.keychain_parse_ok;

  const openDashboard = async () => {
    await invoke('show_main_window_cmd');
    await getCurrentWebviewWindow().hide();
  };

  return (
    <div className="claude-tray-popup">
      <div className="ctp-header">
        <div className="ctp-title">
          <div className="ctp-logo">✦</div>
          <div>
            <div className="ctp-name">Claude Switcher</div>
            <div className="ctp-subtitle">Usage Monitor</div>
          </div>
        </div>
        <div className={proxyOn ? 'ctp-badge running' : 'ctp-badge'}>
          ● {proxyOn ? 'Proxy ON' : 'Proxy OFF'}
        </div>
      </div>

      <div className="ctp-account">
        {accountLabel(data.status)}
        <span className="ctp-plan">{planLabel(data.status)}</span>
        <span className={keychainOk ? 'ctp-auth ok' : 'ctp-auth'}>{keychainOk ? 'AUTH OK' : 'AUTH MISS'}</span>
      </div>

      <div className="ctp-cards">
        <QuotaCard
          icon="⚡"
          title="SESSION EST."
          percent={sessionLeft}
          resetAt={data.usage?.session.reset_at}
        />
        <QuotaCard
          icon="◷"
          title="WEEKLY EST."
          percent={weeklyLeft}
          resetAt={data.usage?.weekly.reset_at}
        />
      </div>

      <div className="ctp-cards">
        <div className="ctp-card today">
          <div className="ctp-card-header">
            <span className="ctp-card-icon">☉</span>
            <span>TODAY</span>
          </div>
          <div className="ctp-card-value today-value">
            {compactNumber(todayTokens)}
            <span className="ctp-remaining">Tokens</span>
          </div>
          <div className="ctp-token-detail">
            {data.usage?.today.message_count ?? 0} usage rows
          </div>
        </div>

        <div className="ctp-card tokens">
          <div className="ctp-card-header">
            <span className="ctp-card-icon">#</span>
            <span>TOKEN USAGE</span>
          </div>
          <div className="ctp-card-value token-value">
            {compactNumber(sessionTokens)}
            <span className="ctp-remaining">Tokens</span>
          </div>
          <div className="ctp-token-detail">
            In {compactNumber(data.usage?.session.totals.input_tokens)} / Out{' '}
            {compactNumber(data.usage?.session.totals.output_tokens)}
          </div>
        </div>
      </div>

      <div className="ctp-meta">
        <span>Model</span>
        <b>{data.usage?.top_model || '暂无'}</b>
      </div>
      <div className="ctp-meta">
        <span>Auto-Claude</span>
        <b>{data.clash?.now || '未读取'}</b>
      </div>

      <div className="ctp-actions">
        <button className="ctp-btn primary" onClick={openDashboard}>
          Dashboard
        </button>
        <button className="ctp-btn" onClick={fetchData} disabled={loading}>
          {loading ? 'Refreshing' : 'Refresh'}
        </button>
      </div>
    </div>
  );
}
