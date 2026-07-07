import { AlertTriangle } from 'lucide-react';

interface ErrorStateProps {
  title?: string;
  message: string;
  onRetry?: () => void;
}

export default function ErrorState({
  title = 'Something went wrong',
  message,
  onRetry,
}: ErrorStateProps) {
  return (
    <div className="panel flex flex-col items-center justify-center gap-3 px-6 py-12 text-center">
      <div className="grid h-12 w-12 place-items-center rounded-full border border-radar-critical/40 bg-radar-critical/10 text-radar-critical">
        <AlertTriangle className="h-5 w-5" />
      </div>
      <h3 className="text-sm font-semibold text-radar-text">{title}</h3>
      <p className="max-w-md text-xs text-radar-muted">{message}</p>
      {onRetry && (
        <button
          type="button"
          onClick={onRetry}
          className="focus-ring mt-2 rounded-md border border-radar-border bg-radar-panel2 px-3 py-1.5 text-xs text-radar-text transition hover:border-radar-accent/40"
        >
          Retry
        </button>
      )}
    </div>
  );
}
