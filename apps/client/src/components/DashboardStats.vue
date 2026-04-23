<script setup lang="ts">
import {
  Shield,
  RefreshCw,
  CheckCircle,
  XCircle,
  Loader2,
} from 'lucide-vue-next';
import type { IOCStats, Feed, SeverityLevel, IOCType } from '../types';

const props = defineProps<{
  stats: IOCStats | null;
  feeds: Feed[];
}>();

const emit = defineEmits<{
  (e: 'toggleSeverity', severity: SeverityLevel): void;
  (e: 'triggerPoll'): void;
}>();

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
            class="flex items-center gap-1"
            :title="`${feed.name} — ${feed.status}${feed.error_msg ? ': ' + feed.error_msg : ''}`"
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
</template>
