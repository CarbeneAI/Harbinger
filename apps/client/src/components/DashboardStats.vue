<script setup lang="ts">
import { ref } from 'vue';
import {
  Shield,
  RefreshCw,
  CheckCircle,
  XCircle,
  Loader2,
  Sparkles,
  CircleSlash,
} from 'lucide-vue-next';
import type { IOCStats, Feed, McpStatus, SeverityLevel, IOCType } from '../types';

const props = defineProps<{
  stats: IOCStats | null;
  feeds: Feed[];
  mcpStatus: McpStatus | null;
}>();

const emit = defineEmits<{
  (e: 'toggleSeverity', severity: SeverityLevel): void;
  (e: 'triggerPoll'): void;
}>();

// Pop-out tooltip rendered via Teleport to escape the top bar's overflow-x-auto
// container. Fixed positioning anchored to the hovered indicator.
// Note: `right` is pre-computed at hover time (window.innerWidth - rect.right)
// so the template doesn't need access to `window` at render time.
type ActivePopover =
  | { kind: 'feed'; feed: Feed; top: number; right: number }
  | { kind: 'mcp'; status: McpStatus; top: number; right: number }
  | null;

const popover = ref<ActivePopover>(null);

function showFeedPopover(event: MouseEvent, feed: Feed) {
  const rect = (event.currentTarget as HTMLElement).getBoundingClientRect();
  popover.value = {
    kind: 'feed',
    feed,
    top: rect.bottom + 8,
    right: window.innerWidth - rect.right,
  };
}

function showMcpPopover(event: MouseEvent, status: McpStatus) {
  const rect = (event.currentTarget as HTMLElement).getBoundingClientRect();
  popover.value = {
    kind: 'mcp',
    status,
    top: rect.bottom + 8,
    right: window.innerWidth - rect.right,
  };
}

function hidePopover() {
  popover.value = null;
}

const IOC_TYPES: { key: IOCType; label: string; color: string }[] = [
  { key: 'ip',     label: 'IP',     color: 'text-blue-400 bg-blue-400/10 border-blue-400/30' },
  { key: 'url',    label: 'URL',    color: 'text-purple-400 bg-purple-400/10 border-purple-400/30' },
  { key: 'domain', label: 'Domain', color: 'text-green-400 bg-green-400/10 border-green-400/30' },
  { key: 'hash',   label: 'Hash',   color: 'text-yellow-400 bg-yellow-400/10 border-yellow-400/30' },
  { key: 'cve',    label: 'CVE',    color: 'text-red-400 bg-red-400/10 border-red-400/30' },
];

const SEVERITY_BADGES: { key: SeverityLevel; label: string; color: string; bg: string }[] = [
  { key: 'critical', label: 'Critical', color: '#f7768e', bg: 'rgba(247,118,142,0.15)' },
  { key: 'high',     label: 'High',     color: '#e0af68', bg: 'rgba(224,175,104,0.15)' },
  { key: 'medium',   label: 'Medium',   color: '#a855f7', bg: 'rgba(168,85,247,0.15)'  },
  { key: 'low',      label: 'Low',      color: '#9ece6a', bg: 'rgba(158,206,106,0.15)' },
];

function getTypeCount(type: IOCType): number {
  return props.stats?.byType?.[type] ?? 0;
}

function getSeverityCount(severity: SeverityLevel): number {
  return props.stats?.bySeverity?.[severity] ?? 0;
}
</script>

<template>
  <div class="flex items-center gap-4 px-4 py-2 bg-bg-secondary border-b border-border-primary overflow-x-auto shrink-0">
    <!-- Left: Wordmark -->
    <div class="flex items-center gap-2 shrink-0">
      <Shield class="w-5 h-5 text-accent-blue" />
      <div>
        <span class="font-logo text-base font-bold text-accent-blue tracking-widest">HARBINGER</span>
        <p class="text-text-tertiary text-xs leading-none">Threat Intelligence</p>
      </div>
    </div>

    <div class="w-px h-8 bg-border-primary shrink-0" />

    <!-- Center: Total + Type Pills -->
    <div class="flex items-center gap-3 flex-1 min-w-0">
      <!-- Total count -->
      <div class="shrink-0">
        <span class="text-2xl font-mono font-bold text-text-primary">
          {{ stats?.totalIOCs?.toLocaleString() ?? '—' }}
        </span>
        <span class="text-xs text-text-tertiary ml-1">IOCs</span>
      </div>

      <!-- Type pills -->
      <div class="flex items-center gap-1.5 overflow-x-auto">
        <template v-for="t in IOC_TYPES" :key="t.key">
          <span
            v-if="getTypeCount(t.key) > 0"
            class="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-xs font-medium border whitespace-nowrap"
            :class="t.color"
          >
            {{ t.label }}
            <span class="font-mono font-bold">{{ getTypeCount(t.key).toLocaleString() }}</span>
          </span>
        </template>
      </div>

      <div class="w-px h-6 bg-border-primary shrink-0" />

      <!-- Severity badges -->
      <div class="flex items-center gap-1.5">
        <button
          v-for="s in SEVERITY_BADGES"
          :key="s.key"
          class="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-xs font-medium border transition-all hover:opacity-90 active:scale-95"
          :style="{
            color: s.color,
            backgroundColor: s.bg,
            borderColor: s.color + '40',
          }"
          :title="`Filter by ${s.label}`"
          @click="emit('toggleSeverity', s.key)"
        >
          {{ s.label }}
          <span class="font-mono font-bold">{{ getSeverityCount(s.key).toLocaleString() }}</span>
        </button>
      </div>
    </div>

    <div class="w-px h-8 bg-border-primary shrink-0" />

    <!-- Right: Feed health -->
    <div class="flex items-center gap-3 shrink-0">
      <div class="flex items-center gap-2">
        <template v-for="feed in feeds" :key="feed.id">
          <div
            class="flex items-center gap-1 cursor-help"
            @mouseenter="showFeedPopover($event, feed)"
            @mouseleave="hidePopover"
          >
            <!-- ok -->
            <CheckCircle
              v-if="feed.status === 'ok'"
              class="w-4 h-4 text-accent-green"
            />
            <!-- pending -->
            <Loader2
              v-else-if="feed.status === 'pending'"
              class="w-4 h-4 text-accent-blue animate-spin"
            />
            <!-- error -->
            <XCircle
              v-else
              class="w-4 h-4 text-severity-critical"
            />
            <span class="text-xs text-text-tertiary font-mono">{{ feed.name }}</span>
          </div>
        </template>

        <!-- cve-mcp enrichment status -->
        <div
          v-if="mcpStatus"
          class="flex items-center gap-1 pl-2 border-l border-border-primary cursor-help"
          @mouseenter="showMcpPopover($event, mcpStatus)"
          @mouseleave="hidePopover"
        >
          <CircleSlash
            v-if="!mcpStatus.enabled"
            class="w-4 h-4 text-text-tertiary"
          />
          <Sparkles
            v-else-if="mcpStatus.connected"
            class="w-4 h-4 text-accent-green"
          />
          <XCircle
            v-else
            class="w-4 h-4 text-severity-critical"
          />
          <span class="text-xs text-text-tertiary font-mono">cve-mcp</span>
          <span
            v-if="mcpStatus.enabled && mcpStatus.connected && mcpStatus.toolCount"
            class="text-xs text-text-tertiary font-mono opacity-60"
          >({{ mcpStatus.toolCount }})</span>
        </div>
      </div>

      <!-- Refresh button -->
      <button
        class="btn-ghost p-1.5 rounded"
        title="Trigger feed poll"
        @click="emit('triggerPoll')"
      >
        <RefreshCw class="w-4 h-4" />
      </button>
    </div>
  </div>

  <!-- Pop-out tooltip — teleported to body so it escapes the top bar's overflow-x-auto clipping -->
  <Teleport to="body">
    <div
      v-if="popover"
      class="fixed z-[9999] rounded-md bg-bg-secondary border border-border-primary shadow-2xl text-xs text-text-primary pointer-events-none"
      :class="popover.kind === 'mcp' ? 'w-80 p-3' : 'w-64 p-2'"
      :style="{
        top: popover.top + 'px',
        left: 'auto',
        right: popover.right + 'px',
      }"
    >
      <!-- Feed popover -->
      <template v-if="popover.kind === 'feed'">
        <div class="font-mono font-semibold mb-1 text-text-primary">{{ popover.feed.name }}</div>
        <div class="text-text-tertiary">
          Status:
          <span
            :class="popover.feed.status === 'ok' ? 'text-accent-green' : popover.feed.status === 'pending' ? 'text-accent-blue' : 'text-severity-critical'"
            class="font-mono"
          >{{ popover.feed.status }}</span>
        </div>
        <div v-if="popover.feed.error_msg" class="text-severity-critical mt-1 break-words">{{ popover.feed.error_msg }}</div>
        <div v-if="popover.feed.last_poll_at" class="text-text-tertiary mt-1">
          Last poll: {{ new Date(popover.feed.last_poll_at).toLocaleTimeString() }}
        </div>
      </template>

      <!-- cve-mcp popover -->
      <template v-else-if="popover.kind === 'mcp'">
        <div class="font-mono font-semibold mb-2 text-text-primary">cve-mcp enrichment</div>
        <div v-if="!popover.status.enabled" class="text-text-tertiary leading-relaxed">
          Disabled. Set <span class="font-mono text-accent-blue">CVE_MCP_ENABLED=true</span> in <span class="font-mono">.env</span> to enable.
        </div>
        <div v-else-if="popover.status.connected">
          <div class="text-accent-green mb-2 font-mono">
            ✓ Connected — {{ popover.status.toolCount }} on-demand tools
          </div>
          <div class="text-text-tertiary leading-relaxed">
            The AI analyst can call these third-party threat-intel APIs during chat and brief generation:
          </div>
          <ul class="mt-2 grid grid-cols-2 gap-x-2 gap-y-0.5 text-text-secondary font-mono text-[11px]">
            <li>• NVD</li>
            <li>• EPSS</li>
            <li>• CISA KEV</li>
            <li>• MITRE ATT&amp;CK</li>
            <li>• AbuseIPDB</li>
            <li>• GreyNoise</li>
            <li>• Shodan</li>
            <li>• VirusTotal</li>
            <li>• URLScan</li>
            <li>• crt.sh</li>
          </ul>
        </div>
        <div v-else>
          <div class="text-severity-critical mb-1 font-mono">✗ Unreachable</div>
          <div v-if="popover.status.lastError" class="text-text-tertiary break-words">{{ popover.status.lastError }}</div>
          <div v-else class="text-text-tertiary">
            Python server not responding. Check <span class="font-mono">~/Dev/cve-mcp-server</span> install.
          </div>
        </div>
      </template>
    </div>
  </Teleport>
</template>
