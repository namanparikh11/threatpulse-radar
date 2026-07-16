/**
 * V6.6 — Asset create / edit dialog.
 *
 * Controlled form for the documented asset schema
 * fields. The dialog is fully keyboard-accessible
 * and renders React text only.
 *
 * The dialog is presentation-only; the parent
 * supplies the submit handler which talks to the
 * EnvironmentContext.
 */

import { useState } from 'react';
import { ASSET_ENVIRONMENTS, ASSET_TYPES, ASSET_CRITICALITIES, ASSET_LIMITS } from '../../environment/schema.mjs';
import ReportDialogShell from '../reports/ReportDialogShell';

export interface AssetDialogProps {
  title: string;
  initial?: any;
  onClose: () => void;
  onSubmit: (args: any) => Promise<{ ok: true; asset: any } | { ok: false; reason: string }>;
}

export default function AssetDialog({ title, initial, onClose, onSubmit }: AssetDialogProps) {
  const [name, setName] = useState(typeof initial?.name === 'string' ? initial.name : '');
  const [description, setDescription] = useState(typeof initial?.description === 'string' ? initial.description : '');
  const [environment, setEnvironment] = useState(typeof initial?.environment === 'string' ? initial.environment : 'unknown');
  const [assetType, setAssetType] = useState(typeof initial?.assetType === 'string' ? initial.assetType : 'other');
  const [localCriticality, setLocalCriticality] = useState(typeof initial?.localCriticality === 'string' ? initial.localCriticality : 'none');
  const [ownerLabel, setOwnerLabel] = useState(typeof initial?.ownerLabel === 'string' ? initial.ownerLabel : '');
  const [tagsText, setTagsText] = useState(Array.isArray(initial?.tags) ? initial.tags.join(', ') : '');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const onSubmitClick = async () => {
    setBusy(true);
    setError(null);
    const tags = tagsText.split(',').map((s: string) => s.trim()).filter(Boolean);
    const r = await onSubmit({ name, description, environment, assetType, localCriticality, ownerLabel, tags });
    if (!r.ok) setError(r.reason);
    setBusy(false);
  };

  return (
    <ReportDialogShell title={title} onClose={onClose}>
      <p className="text-[11px] text-radar-muted">
        <strong>User-assigned local asset criticality</strong> is your own workflow decision; it is not provider severity, CVSS, EPSS, or a ThreatPulse risk score.
      </p>
      <div className="mt-3 grid grid-cols-1 gap-2 md:grid-cols-2">
        <label className="block">
          <span className="text-[11px] text-radar-muted">Name</span>
          <input
            type="text"
            value={name}
            maxLength={ASSET_LIMITS.MAX_ASSET_NAME_CHARS}
            onChange={(e) => setName(e.target.value)}
            className="focus-ring mt-1 w-full rounded-md border border-radar-border bg-radar-panel2 px-2 py-1 text-[12px] text-radar-text"
            aria-label="Asset name"
            data-testid="asset-dialog-name"
          />
        </label>
        <label className="block">
          <span className="text-[11px] text-radar-muted">Environment</span>
          <select
            value={environment}
            onChange={(e) => setEnvironment(e.target.value)}
            className="focus-ring mt-1 w-full rounded-md border border-radar-border bg-radar-panel2 px-2 py-1 text-[12px] text-radar-text"
            aria-label="Environment"
            data-testid="asset-dialog-environment"
          >
            {ASSET_ENVIRONMENTS.map((e) => <option key={e} value={e}>{e}</option>)}
          </select>
        </label>
        <label className="block">
          <span className="text-[11px] text-radar-muted">Type</span>
          <select
            value={assetType}
            onChange={(e) => setAssetType(e.target.value)}
            className="focus-ring mt-1 w-full rounded-md border border-radar-border bg-radar-panel2 px-2 py-1 text-[12px] text-radar-text"
            aria-label="Asset type"
            data-testid="asset-dialog-type"
          >
            {ASSET_TYPES.map((t) => <option key={t} value={t}>{t}</option>)}
          </select>
        </label>
        <label className="block">
          <span className="text-[11px] text-radar-muted">User-assigned local criticality</span>
          <select
            value={localCriticality}
            onChange={(e) => setLocalCriticality(e.target.value)}
            className="focus-ring mt-1 w-full rounded-md border border-radar-border bg-radar-panel2 px-2 py-1 text-[12px] text-radar-text"
            aria-label="Local criticality"
            data-testid="asset-dialog-criticality"
          >
            {ASSET_CRITICALITIES.map((c) => <option key={c} value={c}>{c}</option>)}
          </select>
        </label>
        <label className="block md:col-span-2">
          <span className="text-[11px] text-radar-muted">Owner label</span>
          <input
            type="text"
            value={ownerLabel}
            maxLength={ASSET_LIMITS.MAX_OWNER_LABEL_CHARS}
            onChange={(e) => setOwnerLabel(e.target.value)}
            className="focus-ring mt-1 w-full rounded-md border border-radar-border bg-radar-panel2 px-2 py-1 text-[12px] text-radar-text"
            aria-label="Owner label"
            data-testid="asset-dialog-owner"
          />
        </label>
        <label className="block md:col-span-2">
          <span className="text-[11px] text-radar-muted">Tags (comma-separated)</span>
          <input
            type="text"
            value={tagsText}
            onChange={(e) => setTagsText(e.target.value)}
            className="focus-ring mt-1 w-full rounded-md border border-radar-border bg-radar-panel2 px-2 py-1 text-[12px] text-radar-text"
            aria-label="Tags"
            data-testid="asset-dialog-tags"
          />
        </label>
        <label className="block md:col-span-2">
          <span className="text-[11px] text-radar-muted">Description</span>
          <textarea
            value={description}
            maxLength={ASSET_LIMITS.MAX_ASSET_DESCRIPTION_CHARS}
            onChange={(e) => setDescription(e.target.value)}
            rows={3}
            className="focus-ring mt-1 w-full rounded-md border border-radar-border bg-radar-panel2 px-2 py-1 text-[12px] text-radar-text"
            aria-label="Description"
            data-testid="asset-dialog-description"
          />
        </label>
      </div>
      {error && (
        <p role="alert" aria-live="polite" className="mt-3 rounded-md border border-radar-warn/40 bg-radar-warn/5 px-2 py-1 text-[12px] text-radar-warn">
          {error}
        </p>
      )}
      <div className="mt-4 flex items-center justify-end gap-2">
        <button
          type="button"
          onClick={onClose}
          className="focus-ring inline-flex items-center gap-1 rounded-md border border-radar-border bg-radar-panel2 px-3 py-1.5 text-xs text-radar-muted hover:border-radar-accent/40 hover:text-radar-text"
        >
          Cancel
        </button>
        <button
          type="button"
          onClick={onSubmitClick}
          disabled={busy || name.length === 0}
          className="focus-ring inline-flex items-center gap-1 rounded-md border border-radar-accent/40 bg-radar-accent px-3 py-1.5 text-xs text-radar-panel transition hover:brightness-110 disabled:opacity-50"
          data-testid="asset-dialog-save"
        >
          {busy ? 'Saving…' : 'Save'}
        </button>
      </div>
    </ReportDialogShell>
  );
}
