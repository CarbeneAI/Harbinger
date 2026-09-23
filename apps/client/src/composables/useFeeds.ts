import { ref, onUnmounted } from 'vue';
import type { Feed, IOCStats, EnrichmentStatus } from '../types';
import { API_URL } from './useIOCs';

export function useFeeds() {
  const feeds = ref<Feed[]>([]);
  const stats = ref<IOCStats | null>(null);
  const enrichmentStatus = ref<EnrichmentStatus | null>(null);
  const loading = ref(false);

  let pollInterval: ReturnType<typeof setInterval> | null = null;

  const fetchAll = async (): Promise<void> => {
    loading.value = true;
    try {
      const [feedsRes, statsRes, enrichRes] = await Promise.all([
        fetch(`${API_URL}/feeds`, { credentials: 'include' }),
        fetch(`${API_URL}/stats`, { credentials: 'include' }),
        fetch(`${API_URL}/enrichment/status`, { credentials: 'include' }),
      ]);

      if (feedsRes.ok) {
        const data = await feedsRes.json();
        feeds.value = data.feeds ?? data ?? [];
      }

      if (statsRes.ok) {
        stats.value = await statsRes.json();
      }

      if (enrichRes.ok) {
        enrichmentStatus.value = await enrichRes.json();
      }
    } catch (err) {
      console.error('Failed to fetch feeds/stats/enrichment:', err);
    } finally {
      loading.value = false;
    }
  };

  const triggerPoll = async (): Promise<void> => {
    try {
      await fetch(`${API_URL}/feeds/poll`, { method: 'POST', credentials: 'include' });
      // Re-fetch after 3 second delay to let server update
      setTimeout(() => {
        fetchAll();
      }, 3_000);
    } catch (err) {
      console.error('Failed to trigger poll:', err);
    }
  };

  // Initial fetch
  fetchAll();

  // Poll every 30 seconds
  pollInterval = setInterval(() => {
    fetchAll();
  }, 30_000);

  onUnmounted(() => {
    if (pollInterval) clearInterval(pollInterval);
  });

  return {
    feeds,
    stats,
    enrichmentStatus,
    loading,
    triggerPoll,
  };
}
