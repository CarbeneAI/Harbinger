import type { FeedName } from '../src/types';

export const rawSentinel = 'UNTRUSTED_RECORD_DO_NOT_LOG';
export const credentialSentinel = 'SYNTHETIC_AUTH_KEY_DO_NOT_LOG';
export const cisaRow = {
  cveID: 'CVE-2026-12345', vendorProject: 'Synthetic vendor', product: 'Synthetic product',
  vulnerabilityName: 'Synthetic vulnerability', shortDescription: 'Synthetic description',
  dateAdded: '2026-10-01', knownRansomwareCampaignUse: 'Known',
};
export const urlRow = {
  url: 'http://malware.example.invalid/payload', url_status: 'offline',
  threat: 'malware_download', date_added: '2026-10-01 01:02:03 UTC',
};
export const foxRow = {
  ioc_type: 'domain', ioc: 'c2.example.invalid', confidence_level: 80,
  malware: 'synthetic.family', tags: ['synthetic'],
  first_seen: '2026-10-01 01:02:03 UTC', last_seen: null,
};
export function envelope(feed: FeedName, rows: unknown[]) {
  if (feed === 'cisa_kev') return { catalogVersion: '2026.10.01', dateReleased: '2026-10-01T01:02:03Z', count: rows.length, vulnerabilities: rows };
  if (feed === 'urlhaus') return { query_status: 'ok', urls: rows };
  return { query_status: 'ok', data: rows };
}
export const feeds: FeedName[] = ['cisa_kev', 'urlhaus', 'threatfox'];
export const row = (feed: FeedName) => ({ cisa_kev: cisaRow, urlhaus: urlRow, threatfox: foxRow })[feed];
export interface FeedCase {
  name: string; feed?: FeedName; payload?: unknown; raw?: string;
  reject?: boolean; counts?: [number, number, number]; mapping?: 'defaults' | 'fox-types';
}
export const feedCases: FeedCase[] = [
  { name: 'valid-all', mapping: 'defaults' },
  { name: 'empty-cisa', feed: 'cisa_kev', payload: envelope('cisa_kev', []), counts: [0, 2, 1] },
  { name: 'empty-urlhaus', feed: 'urlhaus', payload: envelope('urlhaus', []), counts: [1, 0, 1] },
  { name: 'empty-threatfox', feed: 'threatfox', payload: envelope('threatfox', []), counts: [1, 2, 0] },
];
for (const feed of feeds) {
  const collection = feed === 'cisa_kev' ? 'vulnerabilities' : feed === 'urlhaus' ? 'urls' : 'data';
  for (const [name, payload] of [
    ['null-envelope', null], ['array-envelope', []], ['missing-envelope-fields', {}],
    ['missing-array', { ...envelope(feed, []), [collection]: undefined }],
    ['null-array', { ...envelope(feed, []), [collection]: null }],
    ['object-instead-of-array', { ...envelope(feed, []), [collection]: {} }],
    ['valid-first-null-later', envelope(feed, [row(feed), null])],
  ] as [string, unknown][]) feedCases.push({ name: `${feed}-${name}`, feed, payload, reject: true });
  feedCases.push({ name: `${feed}-invalid-json`, feed, raw: `{${rawSentinel} ${credentialSentinel}`, reject: true });
}
function invalidRow(feed: FeedName, name: string, field: string, value: unknown) {
  feedCases.push({ name: `${feed}-${name}`, feed, reject: true,
    payload: envelope(feed, [row(feed), { ...row(feed), [field]: value }]) });
}
for (const [name, field, value] of [
  ['missing-version', 'catalogVersion', undefined], ['empty-version', 'catalogVersion', ' '],
  ['bad-release', 'dateReleased', rawSentinel], ['bad-release-type', 'dateReleased', 4],
  ['missing-count', 'count', undefined], ['string-count', 'count', '1'],
  ['negative-count', 'count', -1], ['fraction-count', 'count', 0.5],
  ['unsafe-count', 'count', Number.MAX_SAFE_INTEGER + 1], ['mismatched-count', 'count', 0],
] as [string, string, unknown][]) feedCases.push({ name: `cisa-${name}`, feed: 'cisa_kev', reject: true,
  payload: { ...envelope('cisa_kev', [cisaRow]), [field]: value } });
for (const field of ['vendorProject', 'product', 'vulnerabilityName', 'shortDescription']) invalidRow('cisa_kev', `bad-${field}`, field, { rawSentinel });
invalidRow('cisa_kev', 'missing-cve', 'cveID', undefined);
invalidRow('cisa_kev', 'bad-cve-pattern', 'cveID', 'CVE-invalid-' + rawSentinel);
invalidRow('cisa_kev', 'bad-calendar', 'dateAdded', '2026-02-30');
invalidRow('cisa_kev', 'bad-day-shape', 'dateAdded', '2026-1-1');
invalidRow('cisa_kev', 'bad-day-type', 'dateAdded', 4);
invalidRow('cisa_kev', 'bad-ransomware-type', 'knownRansomwareCampaignUse', null);
feedCases.push({ name: 'cisa-unused-extra-and-nonenum-string', feed: 'cisa_kev',
  payload: envelope('cisa_kev', [{ ...cisaRow, vendorProject: '', knownRansomwareCampaignUse: 'Future label', requiredAction: { ignored: true }, dueDate: false, cwes: 3 }]) });
for (const urls of [undefined, null, []]) feedCases.push({ name: `urlhaus-no-results-${urls === undefined ? 'absent' : urls === null ? 'null' : 'empty'}`,
  feed: 'urlhaus', payload: { query_status: 'no_results', urls }, counts: [1, 0, 1] });
for (const status of ['error-' + rawSentinel, { rawSentinel }, undefined]) feedCases.push({ name: `urlhaus-bad-status-${typeof status}`, feed: 'urlhaus', reject: true,
  payload: { query_status: status, urls: [urlRow] } });
feedCases.push({ name: 'urlhaus-no-results-contradictory', feed: 'urlhaus', reject: true, payload: { query_status: 'no_results', urls: [urlRow] } });
feedCases.push({ name: 'urlhaus-no-results-bad-array', feed: 'urlhaus', reject: true, payload: { query_status: 'no_results', urls: {} } });
invalidRow('urlhaus', 'empty-url', 'url', ' ');
invalidRow('urlhaus', 'bad-url-type', 'url', { rawSentinel });
invalidRow('urlhaus', 'bad-status-type', 'url_status', ['offline']);
invalidRow('urlhaus', 'bad-threat-type', 'threat', { rawSentinel });
invalidRow('urlhaus', 'bad-date', 'date_added', rawSentinel);
invalidRow('urlhaus', 'bad-date-type', 'date_added', 123);
invalidRow('urlhaus', 'empty-date', 'date_added', '');
feedCases.push({ name: 'urlhaus-null-fallbacks-and-unused-tags', feed: 'urlhaus', payload: envelope('urlhaus', [{ ...urlRow, url_status: null, threat: null, date_added: null, tags: { ignored: true } }]) });
for (const status of ['no_result', 'error-' + rawSentinel, { rawSentinel }, undefined]) feedCases.push({ name: `threatfox-bad-status-${typeof status}-${typeof status === 'string' ? status.slice(0, 9) : 'missing'}`, feed: 'threatfox', reject: true,
  payload: { query_status: status, data: [foxRow] } });
invalidRow('threatfox', 'empty-ioc', 'ioc', '');
invalidRow('threatfox', 'bad-ioc-type', 'ioc', { rawSentinel });
invalidRow('threatfox', 'missing-type', 'ioc_type', undefined);
invalidRow('threatfox', 'bad-type-shape', 'ioc_type', 4);
invalidRow('threatfox', 'confidence-string', 'confidence_level', '80');
invalidRow('threatfox', 'confidence-negative', 'confidence_level', -1);
invalidRow('threatfox', 'confidence-too-high', 'confidence_level', 101);
feedCases.push({ name: 'threatfox-confidence-nonfinite', feed: 'threatfox', reject: true,
  raw: JSON.stringify(envelope('threatfox', [foxRow, { ...foxRow, confidence_level: 987654 }])).replace('987654', '1e400') });
invalidRow('threatfox', 'bad-malware', 'malware', { rawSentinel });
invalidRow('threatfox', 'tags-not-array', 'tags', 'synthetic');
invalidRow('threatfox', 'tags-bad-item', 'tags', ['synthetic', { rawSentinel }]);
invalidRow('threatfox', 'bad-first-seen', 'first_seen', rawSentinel);
invalidRow('threatfox', 'bad-last-seen', 'last_seen', { rawSentinel });
invalidRow('threatfox', 'empty-date', 'last_seen', '');
feedCases.push({ name: 'threatfox-null-fallbacks', feed: 'threatfox', payload: envelope('threatfox', [{ ...foxRow, confidence_level: null, malware: null, tags: null, first_seen: null, last_seen: null }]) });
feedCases.push({ name: 'threatfox-unknown-type-skips-unconsumed-fields', feed: 'threatfox',
  payload: envelope('threatfox', [{ ioc_type: 'future_type', ioc: 'future-value', confidence_level: { ignored: true }, malware: [], tags: 4, first_seen: false }, foxRow]) });
feedCases.push({ name: 'threatfox-supported-mappings', feed: 'threatfox', mapping: 'fox-types', counts: [1, 2, 6],
  payload: envelope('threatfox', [
    ['ip:port', '192.0.2.1:443'], ['domain', 'c2.example.invalid'], ['url', 'http://c2.example.invalid/path'],
    ['md5_hash', 'a'.repeat(32)], ['sha256_hash', 'b'.repeat(64)], ['email', 'malware@example.invalid'],
  ].map(([ioc_type, ioc]) => ({ ...foxRow, ioc_type, ioc }))) });

feedCases.push({ name: 'cisa-absent-optional-ransomware', feed: 'cisa_kev',
  payload: envelope('cisa_kev', [{ ...cisaRow, knownRansomwareCampaignUse: undefined }]) });
feedCases.push({ name: 'urlhaus-absent-fallbacks', feed: 'urlhaus', payload: envelope('urlhaus', [{ url: urlRow.url }]) });
feedCases.push({ name: 'urlhaus-retains-nonempty-unparseable-url', feed: 'urlhaus',
  payload: envelope('urlhaus', [{ ...urlRow, url: 'synthetic-unparseable-indicator' }]), counts: [1, 1, 1] });
feedCases.push({ name: 'threatfox-absent-fallbacks', feed: 'threatfox', payload: envelope('threatfox', [{ ioc_type: 'domain', ioc: foxRow.ioc }]) });
