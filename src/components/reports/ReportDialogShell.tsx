/**
 * V6.5 — Report dialog shell.
 *
 * Application-level dialog wrapper. Traps focus
 * inside the dialog, restores focus on close, and
 * closes on `Escape`. The component renders React
 * text only; nothing is built with
 * `dangerouslySetInnerHTML`.
 */

import { useEffect, useId, useRef, type ReactNode } from 'react';
import { X } from 'lucide-react';

export interface ReportDialogShellProps {
  title: string;
  onClose: () => void;
  width?: string;
  children: ReactNode;
}

export default function ReportDialogShell({ title, onClose, width = 'max-w-4xl', children }: ReportDialogShellProps) {
  const ref = useRef<HTMLDivElement | null>(null);
  const previouslyFocused = useRef<HTMLElement | null>(null);
  const titleId = useId();
  useEffect(() => {
    previouslyFocused.current = (document.activeElement as HTMLElement | null) || null;
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') {
        e.stopPropagation();
        onClose();
        return;
      }
      if (e.key === 'Tab' && ref.current) {
        const focusables = ref.current.querySelectorAll<HTMLElement>(
          'button:not([disabled]), [href], input:not([disabled]), select:not([disabled]), textarea:not([disabled]), [tabindex]:not([tabindex="-1"])'
        );
        if (focusables.length === 0) return;
        const first = focusables[0];
        const last = focusables[focusables.length - 1];
        if (e.shiftKey && document.activeElement === first) {
          e.preventDefault();
          last.focus();
        } else if (!e.shiftKey && document.activeElement === last) {
          e.preventDefault();
          first.focus();
        }
      }
    };
    document.addEventListener('keydown', onKey);
    setTimeout(() => {
      const f = ref.current?.querySelector<HTMLElement>(
        'button:not([disabled]), [href], input:not([disabled]), select:not([disabled]), textarea:not([disabled]), [tabindex]:not([tabindex="-1"])'
      );
      f?.focus();
    }, 0);
    return () => {
      document.removeEventListener('keydown', onKey);
      previouslyFocused.current?.focus?.();
    };
  }, [onClose]);
  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center bg-black/40 px-4 py-6"
      role="dialog"
      aria-modal="true"
      aria-labelledby={titleId}
      onClick={(e) => {
        if (e.target === e.currentTarget) onClose();
      }}
    >
      <div
        ref={ref}
        className={[
          'w-full rounded-md border border-radar-border bg-radar-panel p-5 shadow-2xl',
          width,
        ].join(' ')}
        data-testid="report-dialog-shell"
      >
        <div className="flex items-start justify-between gap-3">
          <h2 id={titleId} className="text-sm font-semibold text-radar-text">
            {title}
          </h2>
          <button
            type="button"
            onClick={onClose}
            aria-label="Close report dialog"
            className="focus-ring inline-flex h-7 w-7 items-center justify-center rounded-md border border-radar-border bg-radar-panel2 text-radar-muted hover:border-radar-accent/40 hover:text-radar-text"
          >
            <X className="h-3.5 w-3.5" />
          </button>
        </div>
        <div className="mt-3">{children}</div>
      </div>
    </div>
  );
}
