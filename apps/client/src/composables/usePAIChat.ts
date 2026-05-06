import { ref } from 'vue';
import type { IOC, ChatMessage, QuickPrompts, AIProvider, AIProviderConfig, TokenUsage } from '../types';
import { API_URL } from './useIOCs';

export function usePAIChat() {
  const messages = ref<ChatMessage[]>([]);
  const isLoading = ref(false);
  const error = ref<string | null>(null);
  const quickPrompts = ref<QuickPrompts | null>(null);

  // AI provider state
  const provider = ref<AIProvider>(
    (localStorage.getItem('harbinger-ai-provider') as AIProvider) || 'anthropic'
  );
  const providerConfig = ref<AIProviderConfig>({
    provider: provider.value,
    ollamaUrl: localStorage.getItem('harbinger-ollama-url') || 'http://localhost:11434',
    ollamaModel: localStorage.getItem('harbinger-ollama-model') || '',
    availableModels: [],
  });

  // Fetch available Ollama models from the server
  const loadOllamaModels = async () => {
    try {
      const ollamaUrl = providerConfig.value.ollamaUrl;
      const response = await fetch(
        `${API_URL}/settings/ollama-models?ollamaUrl=${encodeURIComponent(ollamaUrl)}`,
        { credentials: 'include' }
      );
      if (response.ok) {
        const data = await response.json();
        providerConfig.value.availableModels = data.models || [];
        if (!providerConfig.value.ollamaModel && data.models.length > 0) {
          providerConfig.value.ollamaModel = data.models[0];
          localStorage.setItem('harbinger-ollama-model', data.models[0]);
        }
      }
    } catch (err) {
      console.error('Failed to load Ollama models:', err);
      providerConfig.value.availableModels = [];
    }
  };

  // Set AI provider
  const setProvider = (p: AIProvider) => {
    provider.value = p;
    providerConfig.value.provider = p;
    localStorage.setItem('harbinger-ai-provider', p);
    if (p === 'ollama') {
      loadOllamaModels();
    }
  };

  // Set Ollama config
  const setOllamaConfig = (url: string, model: string) => {
    providerConfig.value.ollamaUrl = url;
    providerConfig.value.ollamaModel = model;
    localStorage.setItem('harbinger-ollama-url', url);
    localStorage.setItem('harbinger-ollama-model', model);
  };

  // Load quick prompts
  const loadPrompts = async () => {
    try {
      const response = await fetch(`${API_URL}/chat/prompts`, {
        credentials: 'include',
      });
      if (response.ok) {
        quickPrompts.value = await response.json();
      }
    } catch (err) {
      console.error('Failed to load prompts:', err);
    }
  };

  // Send message to PAI
  const sendMessage = async (
    content: string,
    iocContext?: IOC[]
  ): Promise<boolean> => {
    if (!content.trim()) return false;

    const userMessage: ChatMessage = {
      role: 'user',
      content,
      timestamp: Date.now(),
    };
    messages.value.push(userMessage);

    isLoading.value = true;
    error.value = null;

    try {
      const response = await fetch(`${API_URL}/chat`, {
        method: 'POST',
        credentials: 'include',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          message: content,
          history: messages.value.slice(0, -1).map(m => ({
            role: m.role,
            content: m.content,
          })),
          iocContext,
          sessionId: 'harbinger-dashboard',
          provider: provider.value,
          ollamaUrl: providerConfig.value.ollamaUrl,
          ollamaModel: providerConfig.value.ollamaModel,
        }),
      });

      const data = await response.json();

      if (data.success && data.content) {
        const assistantMessage: ChatMessage = {
          role: 'assistant',
          content: data.content,
          timestamp: Date.now(),
        };
        messages.value.push(assistantMessage);
        return true;
      } else {
        error.value = data.error || 'Failed to get response';
        return false;
      }
    } catch (err) {
      console.error('Chat error:', err);
      error.value = 'Failed to send message';
      return false;
    } finally {
      isLoading.value = false;
    }
  };

  // Quick action with predefined prompt
  const quickAction = async (
    action: keyof QuickPrompts,
    iocContext?: IOC[]
  ): Promise<boolean> => {
    const prompt = quickPrompts.value?.[action];
    if (!prompt) {
      error.value = 'Prompt not available';
      return false;
    }
    return sendMessage(prompt, iocContext);
  };

  // Generate threat brief via dedicated endpoint
  const generateBrief = async (
    briefProvider: AIProvider,
    ollamaUrl?: string,
    ollamaModel?: string
  ): Promise<void> => {
    isLoading.value = true;
    error.value = null;

    try {
      const response = await fetch(`${API_URL}/briefs/generate`, {
        method: 'POST',
        credentials: 'include',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          provider: briefProvider,
          ollamaUrl: ollamaUrl || providerConfig.value.ollamaUrl,
          ollamaModel: ollamaModel || providerConfig.value.ollamaModel,
          iocContext: [],
        }),
      });

      const data = await response.json();

      if (data.success && data.content) {
        const assistantMessage: ChatMessage = {
          role: 'assistant',
          content: `**Threat Brief**\n\n${data.content}`,
          timestamp: Date.now(),
          usage: data.usage as TokenUsage | undefined,
          isBrief: true,
        };
        messages.value.push(assistantMessage);
      } else {
        error.value = data.error || 'Failed to generate brief';
      }
    } catch (err) {
      console.error('Generate brief error:', err);
      error.value = 'Failed to generate threat brief';
    } finally {
      isLoading.value = false;
    }
  };

  // Clear chat history
  const clearChat = () => {
    messages.value = [];
    error.value = null;
  };

  // Initialize
  loadPrompts();
  if (provider.value === 'ollama') {
    loadOllamaModels();
  }

  return {
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
  };
}
