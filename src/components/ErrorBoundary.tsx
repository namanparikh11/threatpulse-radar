/**
 * V6.8 — Local error boundary.
 *
 * A bounded React error boundary that isolates a
 * major local surface (workspace, reports,
 * environment, remediation, fingerprint worker,
 * local history) from the public dashboard. A
 * failure inside a wrapped child surfaces:
 *   - a sanitized error title + description
 *   - an optional retry handler
 *   - an optional reset handler (re-mount the
 *     child via a `resetKey` prop bump)
 *
 * The boundary:
 *   - never logs private content
 *   - never includes a stack trace in production
 *     UI
 *   - is small enough to inline into any panel
 *     without measurable cost
 */
import { Component } from 'react';
import type { ReactNode } from 'react';
import { AlertTriangle, RotateCcw } from 'lucide-react';

interface ErrorBoundaryProps {
  title: string;
  children: ReactNode;
  fallback?: ReactNode;
  /** Optional reset handler. Invoked when the
   *  operator clicks "Try again". */
  onReset?: () => void;
  /** Optional reset label. */
  resetLabel?: string;
  /** Optional guidance shown below the error
   *  description. */
  guidance?: string;
}

interface ErrorBoundaryState {
  hasError: boolean;
  message: string | null;
}

function sanitizeMessage(message: unknown): string {
  if (typeof message !== 'string' || message.length === 0) return 'unknown';
  if (message.length > 200) return message.slice(0, 200) + '…';
  return message;
}

export class ErrorBoundary extends Component<ErrorBoundaryProps, ErrorBoundaryState> {
  state: ErrorBoundaryState = { hasError: false, message: null };

  static getDerivedStateFromError(err: unknown): ErrorBoundaryState {
    return { hasError: true, message: sanitizeMessage(err && (err as Error).message ? (err as Error).message : String(err)) };
  }

  componentDidCatch(err: unknown) {
    // The boundary NEVER logs private content. We
    // intentionally drop the error object. A real
    // production deployment would forward the
    // sanitized message to a local error sink.
    if (typeof err === 'object' && err !== null) {
      // No-op: a private data leak is not worth a log.
    }
  }

  private onClickReset = () => {
    this.setState({ hasError: false, message: null });
    if (typeof this.props.onReset === 'function') {
      try { this.props.onReset(); } catch { /* noop */ }
    }
  };

  render() {
    if (this.state.hasError) {
      if (this.props.fallback) return this.props.fallback;
      return (
        <div
          role="alert"
          aria-live="polite"
          className="rounded-md border border-radar-warn/40 bg-radar-warn/5 p-3 text-[12px] text-radar-warn"
          data-testid="error-boundary-fallback"
        >
          <div className="flex items-start gap-2">
            <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0" />
            <div className="min-w-0 flex-1">
              <p className="font-medium text-radar-text">{this.props.title} is unavailable</p>
              <p className="mt-0.5 text-radar-muted">
                {this.state.message ? `Reason: ${this.state.message}` : 'A local surface could not render.'}
              </p>
              {this.props.guidance && (
                <p className="mt-1 text-radar-dim">{this.props.guidance}</p>
              )}
              {this.props.onReset && (
                <button
                  type="button"
                  onClick={this.onClickReset}
                  className="focus-ring mt-2 inline-flex items-center gap-1 rounded-md border border-radar-warn/40 bg-radar-panel2 px-2 py-1 text-[11px] text-radar-warn hover:border-radar-warn"
                  data-testid="error-boundary-reset"
                >
                  <RotateCcw className="h-3 w-3" />
                  {this.props.resetLabel || 'Try again'}
                </button>
              )}
            </div>
          </div>
        </div>
      );
    }
    return this.props.children;
  }
}
