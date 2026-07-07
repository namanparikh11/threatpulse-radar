import { Inbox } from 'lucide-react';
import type { ReactNode } from 'react';

interface EmptyStateProps {
  title: string;
  description: string;
  action?: ReactNode;
}

export default function EmptyState({ title, description, action }: EmptyStateProps) {
  return (
    <div className="panel flex flex-col items-center justify-center px-6 py-12 text-center">
      <div className="mb-3 grid h-12 w-12 place-items-center rounded-full border border-radar-border bg-radar-panel2 text-radar-muted">
        <Inbox className="h-5 w-5" />
      </div>
      <h3 className="text-sm font-semibold text-radar-text">{title}</h3>
      <p className="mt-1 max-w-sm text-xs text-radar-muted">{description}</p>
      {action && <div className="mt-4">{action}</div>}
    </div>
  );
}
