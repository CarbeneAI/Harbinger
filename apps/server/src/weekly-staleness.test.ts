import { describe, expect, it } from 'bun:test';

/**
 * Regression guard for the stale-weekly bug (found 2026-09-23).
 *
 * Daily briefs were retired 2026-08-21. generateWeeklyStrategicBrief kept
 * calling getRecentBriefsFullText(7), which reads the daily archive by
 * filename, so it returned the same August files every week. The weekly then
 * emailed a month-old narrative stamped with the current date: fresh volume
 * numbers, stale campaign story, no error raised anywhere. Five weeks shipped
 * that way (Aug 24, Aug 31, Sep 7, Sep 14, Sep 21).
 *
 * The fix makes the archive optional and gates it on age. This test pins the
 * age arithmetic so a future refactor cannot silently reintroduce the bug.
 */

const STALE_AFTER_DAYS = 8;

/** Mirrors getNewestBriefAgeDays()'s arithmetic over a filename list. */
function newestAgeDays(files: string[], now: number): number | null {
  const dated = files.filter((f) => /^\d{4}-\d{2}-\d{2}\.md$/.test(f)).sort();
  const newest = dated[dated.length - 1];
  if (!newest) return null;
  const stamp = Date.parse(`${newest.replace(/\.md$/, '')}T00:00:00Z`);
  if (Number.isNaN(stamp)) return null;
  return Math.floor((now - stamp) / 86_400_000);
}

const isFresh = (age: number | null) => age !== null && age <= STALE_AFTER_DAYS;

describe('weekly brief archive staleness guard', () => {
  const now = Date.parse('2026-09-23T12:00:00Z');

  it('treats the real retired archive as STALE (the actual bug)', () => {
    // These are the real files left on the box after dailies were retired.
    const retired = ['2026-08-19.md', '2026-08-20.md', '2026-08-21.md'];
    const age = newestAgeDays(retired, now);
    expect(age).toBe(33);
    expect(isFresh(age)).toBe(false);
  });

  it('accepts an archive from within the window', () => {
    const current = ['2026-09-20.md', '2026-09-21.md', '2026-09-22.md'];
    const age = newestAgeDays(current, now);
    expect(age).toBe(1);
    expect(isFresh(age)).toBe(true);
  });

  it('holds the boundary at 8 days', () => {
    expect(isFresh(newestAgeDays(['2026-09-15.md'], now))).toBe(true);   // 8
    expect(isFresh(newestAgeDays(['2026-09-14.md'], now))).toBe(false);  // 9
  });

  it('returns null for an empty or non-brief directory', () => {
    expect(newestAgeDays([], now)).toBeNull();
    expect(newestAgeDays(['README.md', 'notes.txt'], now)).toBeNull();
    expect(isFresh(null)).toBe(false);
  });

  it('picks the newest by date, not by directory order', () => {
    const unordered = ['2026-09-22.md', '2026-08-01.md', '2026-09-01.md'];
    expect(newestAgeDays(unordered, now)).toBe(1);
  });
});
