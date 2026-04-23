<script setup lang="ts">
import { ref, computed } from 'vue';
import {
  Search,
  Shield,
  Loader2,
  ChevronUp,
  ChevronDown,
} from 'lucide-vue-next';
import type { IOC, IOCType, SeverityLevel, FeedName } from '../types';
import { formatRelativeTime } from '../types';

const props = defineProps<{
  iocs: IOC[];
  total: number;
  loading: boolean;
  selectedIOC: IOC | null;
}>();

const emit = defineEmits<{
  (e: 'select', ioc: IOC): void;
  (e: 'search', value: string): void;
  (e: 'filter', key: 'type' | 'severity' | 'feed', value: string): void;
  (e: 'loadMore'): void;
  (e: 'sort', column: string): void;
}>();

// Local search input (debounced by parent via emitted event)
const searchValue = ref('');
let debounceTimer: ReturnType<typeof setTimeout> | null = null;

const onSearchInput = (e: Event) => {
  const value = (e.target as HTMLInputElement).value;
  searchValue.value = value;
  if (debounceTimer) clearTimeout(debounceTimer);
  debounceTimer = setTimeout(() => {
    emit('search', value);
  }, 300);
};

// Sort state (tracked locally for icon rendering; parent owns actual sort)
const currentSort = ref('last_seen');
const currentSortDir = ref<'asc' | 'desc'>('desc');

const onSort = (column: string) => {
  if (currentSort.value === column) {
    currentSortDir.value = currentSortDir.value === 'asc' ? 'desc' : 'asc';
  } else {
    currentSort.value = column;
    currentSortDir.value = 'desc';
  }
  emit('sort', column);
};

// --- Type badge styling ---
function getTypeBadgeClass(type: IOCType): string {
  const map: Record<IOCType, string> = {
    ip:     'text-blue-400 bg-blue-400/10 border-blue-400/30',
    url:    'text-purple-400 bg-purple-400/10 border-purple-400/30',
    domain: 'text-green-400 bg-green-400/10 border-green-400/30',
    hash:   'text-yellow-400 bg-yellow-400/10 border-yellow-400/30',
    cve:    'text-red-400 bg-red-400/10 border-red-400/30',
    email:  'text-orange-400 bg-orange-400/10 border-orange-400/30',
  };
  return map[type] ?? 'text-text-secondary bg-bg-tertiary border-border-primary';
}

// --- Severity dot color ---
function getSeverityDotColor(severity: SeverityLevel): string {
  const map: Record<SeverityLevel, string> = {
    critical: '#f7768e',
    high:     '#e0af68',
    medium:   '#a855f7',
    low:      '#9ece6a',
  };
  return map[severity] ?? '#94a3b8';
}

// IOC type filter options
const typeOptions: { value: IOCType | ''; label: string }[] = [
  { value: '',       label: 'All Types' },
  { value: 'ip',     label: 'IP Address' },
  { value: 'url',    label: 'URL' },
  { value: 'domain', label: 'Domain' },
  { value: 'hash',   label: 'Hash' },
  { value: 'cve',    label: 'CVE' },
  { value: 'email',  label: 'Email' },
];

const severityOptions: { value: SeverityLevel | ''; label: string }[] = [
  { value: '',         label: 'All Severities' },
  { value: 'critical', label: 'Critical' },
  { value: 'high',     label: 'High' },
  { value: 'medium',   label: 'Medium' },
  { value: 'low',      label: 'Low' },
];

const feedOptions: { value: FeedName | ''; label: string }[] = [
  { value: '',          label: 'All Feeds' },
  { value: 'cisa_kev',  label: 'CISA KEV' },
  { value: 'urlhaus',   label: 'URLhaus' },
  { value: 'threatfox', label: 'ThreatFox' },
];

// Column definitions
interface Column {
  key: string;
  label: string;
  sortable: boolean;
  class?: string;
}

const columns: Column[] = [
  { key: 'severity',  label: 'Sev',       sortable: true,  class: 'w-10' },
  { key: 'ioc_type',  label: 'Type',      sortable: true,  class: 'w-20' },
  { key: 'value',     label: 'Value',     sortable: false, class: 'min-w-0 flex-1' },
  { key: 'title',     label: 'Title',     sortable: false, class: 'w-40 hidden lg:table-cell' },
  { key: 'feed_name', label: 'Source',    sortable: true,  class: 'w-24 hidden md:table-cell' },
  { key: 'last_seen', label: 'Last Seen', sortable: true,  class: 'w-24' },
];

const canLoadMore = computed(() => props.iocs.length < props.total);
</script>

<template>
  <div class="h-full flex flex-col bg-bg-primary">
    <!-- Top controls -->
    <div class="px-4 py-3 border-b border-border-primary space-y-2 shrink-0">
      <div class="flex items-center gap-2">
        <!-- Search -->
        <div class="relative flex-1">
          <Search class="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-text-tertiary pointer-events-none" />
          <input
            type="text"
            class="input pl-9 text-sm"
            :value="searchValue"
            placeholder="Search IOCs..."
            @input="onSearchInput"
          />
        </div>

        <!-- Type filter -->
        <select
          class="input text-sm w-36 shrink-0"
          @change="emit('filter', 'type', ($event.target as HTMLSelectElement).value)"
        >
          <option v-for="o in typeOptions" :key="o.value" :value="o.value">{{ o.label }}</option>
        </select>

        <!-- Severity filter -->
        <select
          class="input text-sm w-36 shrink-0"
          @change="emit('filter', 'severity', ($event.target as HTMLSelectElement).value)"
        >
          <option v-for="o in severityOptions" :key="o.value" :value="o.value">{{ o.label }}</option>
        </select>

        <!-- Feed filter -->
        <select
          class="input text-sm w-32 shrink-0"
          @change="emit('filter', 'feed', ($event.target as HTMLSelectElement).value)"
        >
          <option v-for="o in feedOptions" :key="o.value" :value="o.value">{{ o.label }}</option>
        </select>
      </div>

      <!-- Count label -->
      <div class="flex items-center gap-2">
        <span class="text-xs text-text-tertiary">
          Showing <span class="text-text-secondary font-mono">{{ iocs.length.toLocaleString() }}</span>
          of <span class="text-text-secondary font-mono">{{ total.toLocaleString() }}</span> IOCs
        </span>
        <Loader2 v-if="loading" class="w-3 h-3 text-accent-blue animate-spin" />
      </div>
    </div>

    <!-- Table -->
    <div class="flex-1 overflow-auto" :class="{ 'opacity-60': loading && iocs.length === 0 }">
      <!-- Empty state -->
      <div
        v-if="!loading && iocs.length === 0"
        class="flex flex-col items-center justify-center h-full text-text-tertiary gap-3"
      >
        <Shield class="w-12 h-12 opacity-30" />
        <p class="text-sm">No IOCs found</p>
      </div>

      <!-- Loading skeleton when no data yet -->
      <div v-else-if="loading && iocs.length === 0" class="p-4 space-y-2">
        <div
          v-for="i in 8"
          :key="i"
          class="h-10 bg-bg-secondary rounded animate-pulse"
        />
      </div>

      <!-- Table content -->
      <table v-else class="w-full text-sm border-collapse">
        <thead class="sticky top-0 bg-bg-secondary z-10">
          <tr>
            <th
              v-for="col in columns"
              :key="col.key"
              class="px-3 py-2 text-left text-xs font-medium text-text-tertiary border-b border-border-primary whitespace-nowrap"
              :class="[col.class, col.sortable ? 'cursor-pointer hover:text-text-secondary select-none' : '']"
              @click="col.sortable && onSort(col.key)"
            >
              <span class="flex items-center gap-1">
                {{ col.label }}
                <template v-if="col.sortable && currentSort === col.key">
                  <ChevronUp v-if="currentSortDir === 'asc'" class="w-3 h-3" />
                  <ChevronDown v-else class="w-3 h-3" />
                </template>
              </span>
            </th>
          </tr>
        </thead>

        <tbody>
          <tr
            v-for="ioc in iocs"
            :key="ioc.id"
            class="border-b border-border-primary cursor-pointer transition-colors hover:bg-bg-secondary/50"
            :class="{
              'bg-accent-blue/10 border-l-2 border-l-accent-blue': selectedIOC?.id === ioc.id,
              'border-l-2 border-l-transparent': selectedIOC?.id !== ioc.id,
            }"
            @click="emit('select', ioc)"
          >
            <!-- Severity dot -->
            <td class="px-3 py-2.5 w-10">
              <div
                class="w-2.5 h-2.5 rounded-full"
                :style="{ backgroundColor: getSeverityDotColor(ioc.severity) }"
                :title="ioc.severity"
              />
            </td>

            <!-- Type badge -->
            <td class="px-3 py-2.5 w-20">
              <span
                class="inline-flex items-center px-1.5 py-0.5 rounded text-xs font-medium border uppercase tracking-wide"
                :class="getTypeBadgeClass(ioc.ioc_type)"
              >
                {{ ioc.ioc_type }}
              </span>
            </td>

            <!-- Value (monospace, truncated) -->
            <td class="px-3 py-2.5 min-w-0">
              <span
                class="font-mono text-xs text-text-primary block truncate max-w-xs"
                :title="ioc.value"
              >
                {{ ioc.value }}
              </span>
            </td>

            <!-- Title -->
            <td class="px-3 py-2.5 w-40 hidden lg:table-cell">
              <span
                class="text-xs text-text-secondary block truncate max-w-[10rem]"
                :title="ioc.title"
              >
                {{ ioc.title ?? '—' }}
              </span>
            </td>

            <!-- Source feed -->
            <td class="px-3 py-2.5 w-24 hidden md:table-cell">
              <span class="text-xs text-text-tertiary font-mono">
                {{ ioc.feed_name ?? '—' }}
              </span>
            </td>

            <!-- Last seen (relative) -->
            <td class="px-3 py-2.5 w-24">
              <span class="text-xs text-text-tertiary whitespace-nowrap">
                {{ formatRelativeTime(ioc.last_seen) }}
              </span>
            </td>
          </tr>
        </tbody>
      </table>

      <!-- Load More -->
      <div v-if="canLoadMore && !loading" class="p-4 flex justify-center">
        <button
          class="btn btn-secondary text-sm"
          @click="emit('loadMore')"
        >
          Load More
        </button>
      </div>

      <!-- Still loading more -->
      <div v-if="loading && iocs.length > 0" class="p-4 flex justify-center">
        <Loader2 class="w-5 h-5 text-accent-blue animate-spin" />
      </div>
    </div>
  </div>
</template>
