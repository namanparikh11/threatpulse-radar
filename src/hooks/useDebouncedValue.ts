import { useEffect, useState } from 'react';

/**
 * Debounce a rapidly-changing value (typical use: search input).
 *
 * The returned value lags `value` by `delay` ms. While `value` is changing,
 * `isDebouncing` is true; the consumer can show a "searching…" indicator.
 */
export function useDebouncedValue<T>(value: T, delay: number = 200): {
  debounced: T;
  isDebouncing: boolean;
} {
  const [debounced, setDebounced] = useState(value);
  const [isDebouncing, setIsDebouncing] = useState(false);

  useEffect(() => {
    if (value === debounced) return;
    setIsDebouncing(true);
    const handle = window.setTimeout(() => {
      setDebounced(value);
      setIsDebouncing(false);
    }, delay);
    return () => window.clearTimeout(handle);
    // debounced is intentionally not in deps — we only re-evaluate when
    // the *incoming* value changes.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [value, delay]);

  return { debounced, isDebouncing };
}
