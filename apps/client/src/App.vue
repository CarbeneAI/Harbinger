<script setup lang="ts">
import { ref, computed } from 'vue';
import DashboardStats from './components/DashboardStats.vue';
import IOCTable from './components/IOCTable.vue';
import ChatPanel from './components/ChatPanel.vue';
import { useFeeds } from './composables/useFeeds';
import { useIOCs } from './composables/useIOCs';
import { usePAIChat } from './composables/usePAIChat';
import type { IOC, SeverityLevel, QuickPrompts, AIProvider } from './types';

// --- Data composables ---
const { feeds, stats, mcpStatus, triggerPoll } = useFeeds();
const { iocs, total, loading, setSearch, setFilter, setSort, loadMore, refresh } = useIOCs();

// --- Chat composable ---
const {
  messages,
  isLoading,
  error,
  quickPrompts,
  sendMessage,
  quickAction,
  generateBrief,
  clearChat,
  provider,
  providerConfig,
  setProvider,
  setOllamaConfig,
  loadOllamaModels,
} = usePAIChat();

// --- Selected IOC ---
const selectedIOC = ref<IOC | null>(null);

const selectedIOCs = computed(() =>
  selectedIOC.value ? [selectedIOC.value] : []
);

const handleSelectIOC = (ioc: IOC) => {
  selectedIOC.value = selectedIOC.value?.id === ioc.id ? null : ioc;
};

// --- Severity filter toggle (from stats bar) ---
const activeSeverityFilter = ref<SeverityLevel | null>(null);

const handleToggleSeverity = (severity: SeverityLevel) => {
  if (activeSeverityFilter.value === severity) {
    activeSeverityFilter.value = null;
    setFilter('severity', '');
  } else {
    activeSeverityFilter.value = severity;
    setFilter('severity', severity);
  }
};

// --- IOCTable event handlers ---
const handleSearch = (value: string) => {
  setSearch(value);
};

const handleFilter = (key: 'type' | 'severity' | 'feed', value: string) => {
  setFilter(key, value);
  // Sync severity filter state with stats bar toggle
  if (key === 'severity') {
    activeSeverityFilter.value = value ? (value as SeverityLevel) : null;
  }
};

const handleLoadMore = () => {
  loadMore();
};

const handleSort = (column: string) => {
  setSort(column);
};

// --- Chat event handlers ---
const handleSendMessage = (message: string) => {
  sendMessage(message, selectedIOCs.value);
};

const handleQuickAction = (action: keyof QuickPrompts) => {
  quickAction(action, selectedIOCs.value);
};

const handleSetProvider = (p: AIProvider) => {
  setProvider(p);
};

const handleSetOllamaConfig = (url: string, model: string) => {
  setOllamaConfig(url, model);
  loadOllamaModels();
};

const handleGenerateBrief = () => {
  generateBrief(provider.value, providerConfig.value.ollamaUrl, providerConfig.value.ollamaModel);
};

// --- Feed poll ---
const handleTriggerPoll = async () => {
  await triggerPoll();
  refresh();
};

// --- Resizable split panel ---
const leftPanelPercent = ref(60);
const isResizing = ref(false);

const leftPanelStyle = computed(() => ({ width: `${leftPanelPercent.value}%` }));
const rightPanelStyle = computed(() => ({ width: `${100 - leftPanelPercent.value}%` }));

const startResize = (e: MouseEvent) => {
  isResizing.value = true;
  const container = (e.target as HTMLElement).parentElement!;

  const onMouseMove = (moveEvent: MouseEvent) => {
    const rect = container.getBoundingClientRect();
    const percent = ((moveEvent.clientX - rect.left) / rect.width) * 100;
    leftPanelPercent.value = Math.min(80, Math.max(30, percent));
  };

  const onMouseUp = () => {
    isResizing.value = false;
    document.removeEventListener('mousemove', onMouseMove);
    document.removeEventListener('mouseup', onMouseUp);
  };

  document.addEventListener('mousemove', onMouseMove);
  document.addEventListener('mouseup', onMouseUp);
};
</script>

<template>
  <div class="h-screen flex flex-col bg-bg-primary">
    <!-- Top stats bar -->
    <DashboardStats
      :stats="stats"
      :feeds="feeds"
      :mcp-status="mcpStatus"
      @toggle-severity="handleToggleSeverity"
      @trigger-poll="handleTriggerPoll"
    />

    <!-- Main content - split screen -->
    <div class="flex-1 flex overflow-hidden" :class="{ 'select-none': isResizing }">
      <!-- Left panel - IOC Table (resizable) -->
      <div class="overflow-hidden" :style="leftPanelStyle">
        <IOCTable
          :iocs="iocs"
          :total="total"
          :loading="loading"
          :selected-i-o-c="selectedIOC"
          @select="handleSelectIOC"
          @search="handleSearch"
          @filter="handleFilter"
          @load-more="handleLoadMore"
          @sort="handleSort"
        />
      </div>

      <!-- Resize handle -->
      <div
        class="w-1 flex-shrink-0 bg-border-primary hover:bg-accent-blue cursor-col-resize transition-colors relative group"
        :class="{ 'bg-accent-blue': isResizing }"
        @mousedown="startResize"
      >
        <div class="absolute inset-y-0 -left-1 -right-1" />
      </div>

      <!-- Right panel - PAI Chat -->
      <div class="overflow-hidden" :style="rightPanelStyle">
        <ChatPanel
          :messages="messages"
          :is-loading="isLoading"
          :error="error"
          :quick-prompts="quickPrompts"
          :selected-i-o-cs="selectedIOCs"
          :provider="provider"
          :provider-config="providerConfig"
          @send="handleSendMessage"
          @quick-action="handleQuickAction"
          @clear="clearChat"
          @set-provider="handleSetProvider"
          @set-ollama-config="handleSetOllamaConfig"
          @generate-brief="handleGenerateBrief"
        />
      </div>
    </div>
  </div>
</template>
