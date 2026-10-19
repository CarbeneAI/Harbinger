import { createApp, h, nextTick, ref } from 'vue';
import DOMPurify from 'dompurify';
import ChatPanel from '../../src/components/ChatPanel.vue';
import type { ChatMessage } from '../../src/types';

const messages = ref<ChatMessage[]>([]);
createApp({
  setup: () => () => h(ChatPanel, {
    messages: messages.value,
    isLoading: false,
    error: null,
    quickPrompts: null,
    selectedIOCs: [],
    provider: 'ollama',
    providerConfig: { provider: 'ollama', ollamaUrl: '', ollamaModel: 'fixture', availableModels: [] },
  }),
}).mount('#app');

Object.assign(window, {
  disableSanitizer() { DOMPurify.isSupported = false; },
  async setMarkdown(content: string) {
    messages.value = [{ role: 'assistant', content, timestamp: 0, isBrief: true }];
    await nextTick();
  },
  print() {
    Object.assign(window, { printedHtml: document.querySelector('#print-brief .brief-body')?.innerHTML });
  },
});
