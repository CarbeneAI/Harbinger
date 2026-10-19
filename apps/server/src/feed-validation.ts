/** Validate the consumed response contract before any IOC from that feed is written. */
import type { FeedName } from './types';

type Row = Record<string, unknown>;
const labels: Record<FeedName, string> = { cisa_kev: 'CISA KEV', urlhaus: 'URLhaus', threatfox: 'ThreatFox' };
const foxTypes = new Set(['ip:port', 'domain', 'url', 'md5_hash', 'sha256_hash', 'email']);

function invalid(feed: FeedName): never {
  // Never interpolate untrusted status values, records, or decoding exceptions.
  throw new Error(`Invalid ${labels[feed]} feed response`);
}
function object(value: unknown): value is Row {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}
function nonempty(value: unknown): value is string {
  return typeof value === 'string' && value.trim().length > 0;
}
function date(value: unknown): value is string {
  return nonempty(value) && Number.isFinite(Date.parse(value));
}
function day(value: unknown): value is string {
  return date(value) && /^\d{4}-\d{2}-\d{2}$/.test(value) && new Date(value).toISOString().slice(0, 10) === value;
}
function optionalText(value: unknown): boolean {
  return value === undefined || value === null || typeof value === 'string';
}
function optionalDate(value: unknown): boolean {
  return value === undefined || value === null || date(value);
}
function rows(value: unknown, feed: FeedName): Row[] {
  if (!Array.isArray(value) || !value.every(object)) invalid(feed);
  return value;
}

export async function readFeedJson(response: Response, feed: FeedName): Promise<unknown> {
  try {
    return await response.json();
  } catch {
    return invalid(feed);
  }
}

export function validateCisaKev(value: unknown): Row[] {
  const feed = 'cisa_kev';
  if (!object(value) || !nonempty(value.catalogVersion) || !date(value.dateReleased) ||
      !Number.isSafeInteger(value.count) || (value.count as number) < 0) invalid(feed);
  const entries = rows(value.vulnerabilities, feed);
  if (value.count !== entries.length) invalid(feed);
  for (const entry of entries) {
    if (typeof entry.cveID !== 'string' || !/^CVE-[0-9]{4}-[0-9]{4,19}$/.test(entry.cveID) ||
        !['vendorProject', 'product', 'vulnerabilityName', 'shortDescription'].every(key => typeof entry[key] === 'string') ||
        !day(entry.dateAdded) ||
        (entry.knownRansomwareCampaignUse !== undefined && typeof entry.knownRansomwareCampaignUse !== 'string')) invalid(feed);
  }
  return entries;
}

export function validateUrlhaus(value: unknown): Row[] {
  const feed = 'urlhaus';
  if (!object(value)) invalid(feed);
  if (value.query_status === 'no_results') {
    // The provider documents the status, not every empty-envelope variant.
    // Accept only absent/null/empty rows; contradictory data is not a clean zero.
    if (value.urls === undefined || value.urls === null || (Array.isArray(value.urls) && value.urls.length === 0)) return [];
    invalid(feed);
  }
  if (value.query_status !== 'ok') invalid(feed);
  const entries = rows(value.urls, feed);
  for (const entry of entries) {
    if (!nonempty(entry.url) || !optionalText(entry.url_status) || !optionalText(entry.threat) || !optionalDate(entry.date_added)) invalid(feed);
  }
  return entries;
}

export function validateThreatfox(value: unknown): Row[] {
  const feed = 'threatfox';
  if (!object(value) || value.query_status !== 'ok') invalid(feed);
  const entries = rows(value.data, feed);
  for (const entry of entries) {
    if (!nonempty(entry.ioc_type) || !nonempty(entry.ioc)) invalid(feed);
    // Unknown types are still skipped by the existing mapper. Do not reject
    // fields that mapper never consumes for those rows.
    if (!foxTypes.has(entry.ioc_type)) continue;
    const confidence = entry.confidence_level;
    if ((confidence !== undefined && confidence !== null &&
         (typeof confidence !== 'number' || !Number.isFinite(confidence) || confidence < 0 || confidence > 100)) ||
        !optionalText(entry.malware) ||
        (entry.tags !== undefined && entry.tags !== null && (!Array.isArray(entry.tags) || !entry.tags.every(tag => typeof tag === 'string'))) ||
        !optionalDate(entry.first_seen) || !optionalDate(entry.last_seen)) invalid(feed);
  }
  return entries;
}
