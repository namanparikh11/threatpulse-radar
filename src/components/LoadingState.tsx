import { Loader2 } from 'lucide-react';

interface LoadingStateProps {
  message?: string;
}

export default function LoadingState({ message = 'Loading threat intelligence…' }: LoadingStateProps) {
  return (
    <div className="panel flex flex-col items-center justify-center gap-3 px-6 py-12 text-center">
      <div className="relative grid h-12 w-12 place-items-center rounded-full border border-radar-border bg-radar-panel2">
        <Loader2 className="h-5 w-5 animate-spin text-radar-accent" />
        <span className="pointer-events-none absolute inset-0 animate-ping rounded-full border border-radar-accent/30" />
      </div>
      <p className="text-sm text-radar-muted">{message}</p>
    </div>
  );
}
