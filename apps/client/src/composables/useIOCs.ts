import { ref, onUnmounted } from 'vue';
import type { IOC, IOCType, SeverityLevel, FeedName } from '../types';

function getApiUrl(): string {
  if (import.meta.env.VITE_API_URL) return import.meta.env.VITE_API_URL;
  if (window.location.hostname === 'localhost' || window.location.hostname === '127.0.0.1') {
    return 'http://localhost:4001';
  }
  return 'https://harbinger-api.home.carbeneai.com';
}

export const API_URL = getApiUrl();

const LIMIT = 50;

export function useIOCs() {
  const iocs = ref<IOC[]>([]);
  const total = ref(0);
  const loading = ref(false);

  // Filter state
  const search = ref('');
  const typeFilter = ref<IOCType | ''>('');
  const severityFilter = ref<SeverityLevel | ''>('');
  const feedFilter = ref<FeedName | ''>('');
  const sort = ref('last_seen');
  const sortDir = ref<'asc' | 'desc'>('desc');

  // Pagination offset
  let offset = 0;

  // Debounce timer
  let searchTimer: ReturnType<typeof setTimeout> | null = null;
  let pollInterval: ReturnType<typeof setInterval> | null = null;

  const buildQuery = (currentOffset: number): string => {
    const params = new URLSearchParams();
    params.set('limit', String(LIMIT));
    params.set('offset', String(currentOffset));
    if (search.value) params.set('search', search.value);
    if (typeFilter.value) params.set('type', typeFilter.value);
    if (severityFilter.value) params.set('severity', severityFilter.value);
    if (feedFilter.value) params.set('feed', feedFilter.value);
    if (sort.value) params.set('sort', sort.value);
    if (sortDir.value) params.set('sortDir', sortDir.value);
    return params.toString();
  };

  const fetchIOCs = async (reset = false): Promise<void> => {
    if (reset) {
      offset = 0;
    }

    loading.value = true;

    try {
      const query = buildQuery(offset);
      const response = await fetch(`${API_URL}/iocs?${query}`);
      if (!response.ok) throw new Error(`HTTP ${response.status}`);
      const data = await response.json();

      const fetched: IOC[] = data.iocs ?? [];
      total.value = data.total ?? 0;

      if (reset) {
        iocs.value = fetched;
      } else {
        iocs.value = [...iocs.value, ...fetched];
      }
    } catch (err) {
      console.error('Failed to fetch IOCs:', err);
    } finally {
      loading.value = false;
    }
  };

  const setSearch = (value: string) => {
    search.value = value;
    if (searchTimer) clearTimeout(searchTimer);
    searchTimer = setTimeout(() => {
      fetchIOCs(true);
    }, 300);
  };

  const setFilter = (key: 'type' | 'severity' | 'feed', value: string) => {
    if (key === 'type') typeFilter.value = value as IOCType | '';
    if (key === 'severity') severityFilter.value = value as SeverityLevel | '';
    if (key === 'feed') feedFilter.value = value as FeedName | '';
    fetchIOCs(true);
  };

  const setSort = (column: string) => {
    if (sort.value === column) {
      sortDir.value = sortDir.value === 'asc' ? 'desc' : 'asc';
    } else {
      sort.value = column;
      sortDir.value = 'desc';
    }
    fetchIOCs(true);
  };

  const loadMore = () => {
    if (iocs.value.length >= total.value) return;
    offset += LIMIT;
    fetchIOCs(false);
  };

  const refresh = () => {
    fetchIOCs(true);
  };

  // Initial fetch
  fetchIOCs(true);

  // Poll every 60 seconds
  pollInterval = setInterval(() => {
    fetchIOCs(true);
  }, 60_000);

  onUnmounted(() => {
    if (pollInterval) clearInterval(pollInterval);
    if (searchTimer) clearTimeout(searchTimer);
  });

  return {
    iocs,
    total,
    loading,
    filters: {
      search,
      type: typeFilter,
      severity: severityFilter,
      feed: feedFilter,
      sort,
      sortDir,
    },
    setSearch,
    setFilter,
    setSort,
    loadMore,
    refresh,
  };
}
