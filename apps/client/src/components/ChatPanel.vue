<script setup lang="ts">
import { ref, computed, nextTick, watch } from 'vue';
import { marked } from 'marked';
import {
  Send,
  Trash2,
  Loader2,
  Shield,
  User,
  Search,
  FileText,
  Terminal,
  Map,
  Cloud,
  Server,
  Settings,
  Save,
  Check,
} from 'lucide-vue-next';
import type { IOC, ChatMessage, QuickPrompts, AIProvider, AIProviderConfig } from '../types';
import { formatRelativeTime } from '../types';

// Configure marked for analyst output
marked.setOptions({
  breaks: true,
  gfm: true,
});

const renderMarkdown = (content: string): string => {
  return marked.parse(content) as string;
};

const props = defineProps<{
  messages: ChatMessage[];
  isLoading: boolean;
  error: string | null;
  quickPrompts: QuickPrompts | null;
  selectedIOCs: IOC[];
  provider: AIProvider;
  providerConfig: AIProviderConfig;
}>();

const emit = defineEmits<{
  (e: 'send', message: string): void;
  (e: 'quickAction', action: keyof QuickPrompts): void;
  (e: 'clear'): void;
  (e: 'setProvider', provider: AIProvider): void;
  (e: 'setOllamaConfig', url: string, model: string): void;
  (e: 'generateBrief'): void;
}>();

const showSettings = ref(false);
const editOllamaUrl = ref(props.providerConfig.ollamaUrl);
const editOllamaModel = ref(props.providerConfig.ollamaModel);
const settingsSaved = ref(false);

// Sync local edits when props change
watch(() => props.providerConfig.ollamaModel, (v) => { editOllamaModel.value = v; });
watch(() => props.providerConfig.ollamaUrl, (v) => { editOllamaUrl.value = v; });

const saveSettings = () => {
  emit('setOllamaConfig', editOllamaUrl.value, editOllamaModel.value);
  settingsSaved.value = true;
  setTimeout(() => { settingsSaved.value = false; }, 2000);
};

const inputRef = ref<HTMLTextAreaElement | null>(null);
const messagesRef = ref<HTMLDivElement | null>(null);
const inputText = ref('');

// Auto-scroll to bottom when new messages arrive
watch(() => props.messages.length, async () => {
  await nextTick();
  if (messagesRef.value) {
    messagesRef.value.scrollTop = messagesRef.value.scrollHeight;
  }
});

// IOC context summary for the context badge
const selectedIOCSummary = computed(() => {
  if (props.selectedIOCs.length === 0) return null;
  if (props.selectedIOCs.length === 1) {
    const ioc = props.selectedIOCs[0];
    return { value: ioc.value, type: ioc.ioc_type };
  }
  return { value: `${props.selectedIOCs.length} IOCs selected`, type: null };
});

const handleSend = () => {
  const message = inputText.value.trim();
  if (message && !props.isLoading) {
    emit('send', message);
    inputText.value = '';
  }
};

const handleKeyDown = (e: KeyboardEvent) => {
  if (e.key === 'Enter' && !e.shiftKey) {
    e.preventDefault();
    handleSend();
  }
};

const formatTime = (timestamp: number) => {
  return new Date(timestamp).toLocaleTimeString('en-US', {
    hour: '2-digit',
    minute: '2-digit',
  });
};

// Type badge helper for context display
function getTypeBadgeClass(type: string): string {
  const map: Record<string, string> = {
    ip:     'text-blue-400 bg-blue-400/10',
    url:    'text-purple-400 bg-purple-400/10',
    domain: 'text-green-400 bg-green-400/10',
    hash:   'text-yellow-400 bg-yellow-400/10',
    cve:    'text-red-400 bg-red-400/10',
    email:  'text-orange-400 bg-orange-400/10',
  };
  return map[type] ?? 'text-text-secondary bg-bg-tertiary';
}

const quickActions = [
  { key: 'analyze' as const, label: 'Analyze',      icon: Search   },
  { key: 'brief'   as const, label: 'Threat Brief', icon: FileText },
  { key: 'hunt'    as const, label: 'Hunt Queries', icon: Terminal },
  { key: 'mitre'   as const, label: 'MITRE Map',    icon: Map      },
];
</script>

<template>
  <div class="h-full flex flex-col bg-bg-primary">
    <!-- Header -->
    <div class="px-4 py-3 border-b border-border-primary shrink-0">
      <div class="flex items-center justify-between">
        <div class="flex items-center gap-2">
          <Shield class="w-5 h-5 text-accent-blue" />
          <h2 class="font-medium text-text-primary">Harbinger Analyst</h2>
        </div>

        <div class="flex items-center gap-2">
          <!-- AI Provider Toggle -->
          <div class="flex items-center gap-1 bg-bg-secondary rounded-full p-0.5">
            <button
              class="flex items-center gap-1 px-2 py-1 rounded-full text-xs transition-colors"
              :class="provider === 'anthropic'
                ? 'bg-accent-blue text-white'
                : 'text-text-tertiary hover:text-text-secondary'"
              title="Cloud AI (Anthropic Claude)"
              @click="emit('setProvider', 'anthropic')"
            >
              <Cloud class="w-3 h-3" />
              <span>Cloud</span>
            </button>
            <button
              class="flex items-center gap-1 px-2 py-1 rounded-full text-xs transition-colors"
              :class="provider === 'ollama'
                ? 'bg-accent-green text-bg-primary'
                : 'text-text-tertiary hover:text-text-secondary'"
              title="Local AI (Ollama)"
              @click="emit('setProvider', 'ollama')"
            >
              <Server class="w-3 h-3" />
              <span>Local</span>
            </button>
          </div>

          <!-- Settings gear (for Ollama config) -->
          <button
            v-if="provider === 'ollama'"
            class="btn-ghost p-1 rounded"
            title="Ollama settings"
            @click="showSettings = !showSettings"
          >
            <Settings class="w-4 h-4" />
          </button>

          <!-- Generate Brief button -->
          <button
            class="flex items-center gap-1 px-2 py-1 text-xs rounded border border-border-primary text-text-secondary hover:text-accent-blue hover:border-accent-blue transition-colors"
            title="Generate threat brief from current IOC landscape"
            @click="emit('generateBrief')"
          >
            <FileText class="w-3 h-3" />
            <span>Brief</span>
          </button>

          <!-- Clear chat -->
          <button
            v-if="messages.length > 0"
            class="btn-ghost p-1 rounded"
            title="Clear chat"
            @click="emit('clear')"
          >
            <Trash2 class="w-4 h-4" />
          </button>
        </div>
      </div>

      <!-- Ollama Settings Panel -->
      <div
        v-if="showSettings && provider === 'ollama'"
        class="mt-2 p-3 bg-bg-secondary rounded border border-border-primary space-y-2"
      >
        <div>
          <label class="text-xs text-text-tertiary block mb-1">Ollama URL</label>
          <input
            type="text"
            class="input text-xs w-full"
            v-model="editOllamaUrl"
            placeholder="http://localhost:11434"
          />
        </div>
        <div>
          <label class="text-xs text-text-tertiary block mb-1">Model</label>
          <select
            v-if="providerConfig.availableModels.length > 0"
            class="input text-xs w-full"
            v-model="editOllamaModel"
          >
            <option v-for="model in providerConfig.availableModels" :key="model" :value="model">
              {{ model }}
            </option>
          </select>
          <input
            v-else
            type="text"
            class="input text-xs w-full"
            v-model="editOllamaModel"
            placeholder="llama3.1, qwen2.5, etc."
          />
        </div>
        <div class="flex items-center justify-between">
          <p class="text-xs text-text-tertiary">
            <Server class="w-3 h-3 inline" /> Data stays on your network
          </p>
          <button
            class="flex items-center gap-1 px-3 py-1.5 text-xs rounded border transition-colors"
            :class="settingsSaved
              ? 'border-accent-green text-accent-green'
              : 'border-accent-blue text-accent-blue hover:bg-accent-blue/10'"
            @click="saveSettings"
          >
            <Check v-if="settingsSaved" class="w-3 h-3" />
            <Save v-else class="w-3 h-3" />
            {{ settingsSaved ? 'Saved' : 'Save' }}
          </button>
        </div>
      </div>

      <!-- Selected IOC context badge -->
      <div
        v-if="selectedIOCSummary"
        class="mt-2 px-2 py-1.5 bg-bg-secondary rounded text-xs text-text-secondary flex items-center gap-2"
      >
        <span class="text-accent-blue shrink-0">Context:</span>
        <span class="font-mono truncate">{{ selectedIOCSummary.value }}</span>
        <span
          v-if="selectedIOCSummary.type"
          class="shrink-0 px-1.5 py-0.5 rounded text-xs font-medium uppercase"
          :class="getTypeBadgeClass(selectedIOCSummary.type)"
        >
          {{ selectedIOCSummary.type }}
        </span>
      </div>
    </div>

    <!-- Quick actions -->
    <div class="px-4 py-2 border-b border-border-primary flex gap-2 overflow-x-auto shrink-0">
      <button
        v-for="action in quickActions"
        :key="action.key"
        class="flex items-center gap-1.5 px-3 py-1.5 text-xs rounded-full border border-border-primary
               text-text-secondary hover:text-text-primary hover:border-accent-blue hover:bg-accent-blue/10
               transition-colors whitespace-nowrap disabled:opacity-50 disabled:cursor-not-allowed"
        :disabled="isLoading || selectedIOCs.length === 0"
        :title="selectedIOCs.length === 0 ? 'Select an IOC first' : action.label"
        @click="emit('quickAction', action.key)"
      >
        <component :is="action.icon" class="w-3 h-3" />
        {{ action.label }}
      </button>
    </div>

    <!-- Messages -->
    <div ref="messagesRef" class="flex-1 overflow-y-auto px-4 py-4 space-y-4">
      <template v-if="messages.length > 0">
        <div
          v-for="(msg, index) in messages"
          :key="index"
          class="flex gap-3"
          :class="msg.role === 'user' ? 'justify-end' : 'justify-start'"
        >
          <!-- Assistant avatar -->
          <div
            v-if="msg.role === 'assistant'"
            class="w-8 h-8 rounded-full bg-accent-blue/20 flex items-center justify-center flex-shrink-0"
          >
            <Shield class="w-4 h-4 text-accent-blue" />
          </div>

          <!-- Message bubble -->
          <div
            class="max-w-[80%] px-3 py-2 rounded-lg"
            :class="msg.role === 'user'
              ? 'bg-accent-blue text-white'
              : 'bg-bg-secondary text-text-primary'"
          >
            <div
              v-if="msg.role === 'assistant'"
              class="text-sm prose prose-invert prose-sm max-w-none"
              v-html="renderMarkdown(msg.content)"
            />
            <p v-else class="text-sm whitespace-pre-wrap">{{ msg.content }}</p>
            <span class="text-xs opacity-60 mt-1 block">
              {{ formatTime(msg.timestamp) }}
            </span>
          </div>

          <!-- User avatar -->
          <div
            v-if="msg.role === 'user'"
            class="w-8 h-8 rounded-full bg-bg-tertiary flex items-center justify-center flex-shrink-0"
          >
            <User class="w-4 h-4 text-text-secondary" />
          </div>
        </div>
      </template>

      <!-- IOC detail card (shown when IOC selected but no messages yet) -->
      <div v-else-if="selectedIOCs.length > 0" class="px-2 py-4 space-y-3">
        <div
          v-for="ioc in selectedIOCs"
          :key="ioc.id"
          class="bg-bg-secondary rounded-lg border border-border-primary p-4 space-y-3"
        >
          <div class="flex items-center gap-2">
            <span
              class="w-2.5 h-2.5 rounded-full shrink-0"
              :class="{
                'bg-severity-critical': ioc.severity === 'critical',
                'bg-severity-high': ioc.severity === 'high',
                'bg-severity-medium': ioc.severity === 'medium',
                'bg-severity-low': ioc.severity === 'low',
              }"
            />
            <span
              class="px-1.5 py-0.5 rounded text-xs font-mono font-medium uppercase"
              :class="getTypeBadgeClass(ioc.ioc_type)"
            >{{ ioc.ioc_type }}</span>
            <span class="text-xs text-text-tertiary capitalize">{{ ioc.severity }}</span>
          </div>

          <p class="font-mono text-sm text-accent-blue break-all">{{ ioc.value }}</p>

          <p v-if="ioc.title" class="text-sm text-text-primary">{{ ioc.title }}</p>
          <p v-if="ioc.description" class="text-xs text-text-secondary leading-relaxed">{{ ioc.description }}</p>

          <div class="flex flex-wrap gap-x-4 gap-y-1 text-xs text-text-tertiary">
            <span v-if="ioc.feed_name">Source: <span class="text-text-secondary">{{ ioc.feed_name }}</span></span>
            <span v-if="ioc.first_seen">First seen: <span class="text-text-secondary">{{ formatRelativeTime(ioc.first_seen) }}</span></span>
            <span v-if="ioc.last_seen">Last seen: <span class="text-text-secondary">{{ formatRelativeTime(ioc.last_seen) }}</span></span>
            <span v-if="ioc.source_ref">
              <a :href="ioc.source_ref" target="_blank" class="text-accent-blue hover:underline">Reference</a>
            </span>
          </div>

          <div v-if="ioc.tags && ioc.tags.length > 0" class="flex flex-wrap gap-1">
            <span
              v-for="tag in ioc.tags"
              :key="tag"
              class="px-1.5 py-0.5 bg-bg-tertiary rounded text-xs text-text-tertiary"
            >{{ tag }}</span>
          </div>
        </div>
        <p class="text-xs text-text-tertiary text-center">Use the quick actions above or ask a question to analyze this IOC.</p>
      </div>

      <!-- Empty state (no IOC selected, no messages) -->
      <div v-else class="h-full flex flex-col items-center justify-center text-text-tertiary">
        <Shield class="w-12 h-12 mb-3 opacity-30" />
        <p class="text-sm text-center">
          Select an IOC to analyze,<br>or generate a threat brief.
        </p>
      </div>

      <!-- Loading indicator -->
      <div v-if="isLoading" class="flex gap-3">
        <div class="w-8 h-8 rounded-full bg-accent-blue/20 flex items-center justify-center">
          <Loader2 class="w-4 h-4 text-accent-blue animate-spin" />
        </div>
        <div class="px-3 py-2 bg-bg-secondary rounded-lg">
          <p class="text-sm text-text-tertiary">Analyzing...</p>
        </div>
      </div>

      <!-- Error message -->
      <div
        v-if="error"
        class="px-3 py-2 bg-severity-critical-bg text-severity-critical rounded-lg text-sm"
      >
        {{ error }}
      </div>
    </div>

    <!-- Input area -->
    <div class="p-4 border-t border-border-primary shrink-0">
      <div class="flex gap-2">
        <textarea
          ref="inputRef"
          v-model="inputText"
          class="input resize-none"
          rows="2"
          placeholder="Ask about the selected IOC..."
          :disabled="isLoading"
          @keydown="handleKeyDown"
        />
        <button
          class="btn btn-primary px-3 self-end"
          :disabled="!inputText.trim() || isLoading"
          @click="handleSend"
        >
          <Send class="w-4 h-4" />
        </button>
      </div>
    </div>
  </div>
</template>
