/**
 * V6.6 — Environment panel.
 *
 * Operator surface for the local environment
 * database. Renders the count cards, the asset
 * list, the import + export + clear actions, and
 * the correlation queue. The component is purely
 * a presentational layer over the EnvironmentContext
 * value; all state lives in the context.
 *
 * Privacy copy is rendered at the top of the panel
 * so the operator is reminded that the data is
 * local-only.
 */

import { useCallback, useMemo, useState } from 'react';
import { Archive, Database, FileSearch, HardDrive, Plus, ShieldAlert, Trash2, Upload } from 'lucide-react';
import { useEnvironment } from '../../state/EnvironmentContext';
import AssetDialog from './AssetDialog';
import InventoryImportDialog from './InventoryImportDialog';
import CorrelationQueue from './CorrelationQueue';

export default function EnvironmentPanel() {
  const env = useEnvironment();
  const [showCreateAsset, setShowCreateAsset] = useState(false);
  const [editingAsset, setEditingAsset] = useState<any | null>(null);
  const [showImport, setShowImport] = useState(false);
  const [showClearConfirm, setShowClearConfirm] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const liveAssets = useMemo(() => env.state.assets.filter((a: any) => !a.archived), [env.state.assets]);
  const archivedCount = env.state.assets.length - liveAssets.length;

  const componentCount = useMemo(() => {
    let n = 0;
    for (const a of liveAssets) n += (env.state.componentsByAsset[a.assetId] || []).length;
    return n;
  }, [liveAssets, env.state.componentsByAsset]);

  const inventoryCount = useMemo(() => {
    let n = 0;
    for (const a of liveAssets) n += (env.state.inventoriesByAsset[a.assetId] || []).length;
    return n;
  }, [liveAssets, env.state.inventoriesByAsset]);

  const correlationCount = useMemo(() => {
    let n = 0;
    for (const a of liveAssets) {
      for (const inv of (env.state.inventoriesByAsset[a.assetId] || [])) {
        n += (env.state.correlationsByInventory[inv.inventoryId] || []).length;
      }
    }
    return n;
  }, [liveAssets, env.state.inventoriesByAsset, env.state.correlationsByInventory]);

  const handleArchive = useCallback(async (asset: any) => {
    setError(null);
    const r = await env.archiveAsset(asset.assetId);
    if (!r.ok) setError(`Could not archive: ${r.reason}`);
  }, [env]);

  const handleClear = useCallback(async () => {
    setError(null);
    const r = await env.clearEnvironment();
    if (!r.ok) setError(`Could not clear: ${r.reason}`);
    setShowClearConfirm(false);
  }, [env]);

  if (env.state.status === 'initializing') {
    return (
      <section className="panel px-4 py-3 text-[12px] text-radar-muted" aria-busy="true">
        Initialising local environment...
      </section>
    );
  }

  if (env.state.status === 'unavailable') {
    return (
      <section className="panel border-radar-warn/40 bg-radar-warn/5 px-4 py-3 text-[12px] text-radar-warn" role="status" aria-live="polite">
        <p>
          Local environment is unavailable in this browser session ({env.state.lastError || 'unknown reason'}). Asset and SBOM data cannot be saved.
        </p>
      </section>
    );
  }

  return (
    <section className="panel space-y-3 px-4 py-4" aria-label="Local environment">
      <header className="flex flex-wrap items-start justify-between gap-2">
        <div>
          <h2 className="text-sm font-semibold text-radar-text">My environment</h2>
          <p className="mt-1 text-[11px] text-radar-muted" data-testid="environment-privacy-preamble">
            Asset names, SBOMs, components, correlations, and review notes are stored only in this browser.
          </p>
          <p className="mt-1 text-[11px] text-radar-muted">
            Correlation shows potential local relevance based on imported component identity and available public data. It does not prove exploitability or compromise.
          </p>
        </div>
        <div className="flex flex-wrap items-center gap-2">
          {env.state.status === 'session-only' && (
            <span className="inline-flex items-center gap-1 rounded-md border border-radar-warn/40 bg-radar-warn/5 px-2 py-1 text-[10px] text-radar-warn" data-testid="environment-status">
              <ShieldAlert className="h-3 w-3" />
              Session-only — data will not survive a tab close
            </span>
          )}
          <button
            type="button"
            onClick={() => setShowCreateAsset(true)}
            className="focus-ring inline-flex items-center gap-1 rounded-md border border-radar-accent/40 bg-radar-accent/10 px-2.5 py-1.5 text-xs text-radar-accent transition hover:border-radar-accent"
            data-testid="environment-new-asset"
          >
            <Plus className="h-3.5 w-3.5" />
            New asset
          </button>
          <button
            type="button"
            onClick={() => setShowImport(true)}
            className="focus-ring inline-flex items-center gap-1 rounded-md border border-radar-accent/40 bg-radar-accent px-2.5 py-1.5 text-xs text-radar-panel transition hover:brightness-110"
            data-testid="environment-import"
            disabled={liveAssets.length === 0}
          >
            <Upload className="h-3.5 w-3.5" />
            Import SBOM
          </button>
        </div>
      </header>

      <div className="grid grid-cols-2 gap-2 sm:grid-cols-4">
        <CountCard icon={<HardDrive className="h-3.5 w-3.5" />} label="Assets" value={liveAssets.length} />
        <CountCard icon={<Database className="h-3.5 w-3.5" />} label="Components" value={componentCount} />
        <CountCard icon={<FileSearch className="h-3.5 w-3.5" />} label="Correlations" value={correlationCount} />
        <CountCard icon={<Archive className="h-3.5 w-3.5" />} label="Inventories" value={inventoryCount} />
      </div>

      {error && (
        <p role="alert" aria-live="polite" className="rounded-md border border-radar-warn/40 bg-radar-warn/5 px-2 py-1 text-[12px] text-radar-warn" data-testid="environment-error">
          {error}
        </p>
      )}

      <div className="rounded-md border border-radar-border bg-radar-panel2/40">
        <table className="w-full border-collapse text-[12px]">
          <caption className="sr-only">Local assets</caption>
          <thead>
            <tr className="text-left text-[10px] uppercase tracking-wider text-radar-muted">
              <th scope="col" className="border-b border-radar-border/40 px-2 py-1">Name</th>
              <th scope="col" className="border-b border-radar-border/40 px-2 py-1">Environment</th>
              <th scope="col" className="border-b border-radar-border/40 px-2 py-1">Type</th>
              <th scope="col" className="border-b border-radar-border/40 px-2 py-1">Local criticality</th>
              <th scope="col" className="border-b border-radar-border/40 px-2 py-1">Status</th>
              <th scope="col" className="border-b border-radar-border/40 px-2 py-1">Actions</th>
            </tr>
          </thead>
          <tbody>
            {liveAssets.length === 0 ? (
              <tr><td colSpan={6} className="px-2 py-3 text-center text-[11px] text-radar-dim">No assets yet. Click "New asset" to begin.</td></tr>
            ) : (
              liveAssets.map((a: any) => (
                <tr key={a.assetId} className="align-top">
                  <td className="border-b border-radar-border/40 px-2 py-1 text-radar-text">{a.name}<div className="text-[10px] text-radar-dim">{a.assetId}</div></td>
                  <td className="border-b border-radar-border/40 px-2 py-1 text-radar-muted">{a.environment}</td>
                  <td className="border-b border-radar-border/40 px-2 py-1 text-radar-muted">{a.assetType}</td>
                  <td className="border-b border-radar-border/40 px-2 py-1 text-radar-muted">{a.localCriticality}</td>
                  <td className="border-b border-radar-border/40 px-2 py-1 text-radar-muted">{a.archived ? 'archived' : 'active'}</td>
                  <td className="border-b border-radar-border/40 px-2 py-1">
                    <div className="flex flex-wrap items-center gap-1">
                      <button
                        type="button"
                        onClick={() => setEditingAsset(a)}
                        className="focus-ring inline-flex items-center gap-1 rounded-md border border-radar-border bg-radar-panel2 px-1.5 py-0.5 text-[10px] text-radar-muted hover:border-radar-accent/40 hover:text-radar-text"
                        data-testid={`environment-asset-edit-${a.assetId}`}
                      >
                        Edit
                      </button>
                      <button
                        type="button"
                        onClick={() => handleArchive(a)}
                        className="focus-ring inline-flex items-center gap-1 rounded-md border border-radar-border bg-radar-panel2 px-1.5 py-0.5 text-[10px] text-radar-muted hover:border-radar-warn/40 hover:text-radar-warn"
                        data-testid={`environment-asset-archive-${a.assetId}`}
                      >
                        Archive
                      </button>
                    </div>
                  </td>
                </tr>
              ))
            )}
            {archivedCount > 0 && (
              <tr><td colSpan={6} className="px-2 py-1 text-[10px] text-radar-dim">{archivedCount} archived asset(s) hidden</td></tr>
            )}
          </tbody>
        </table>
      </div>

      {liveAssets.length > 0 && (
        <CorrelationQueue assets={liveAssets} />
      )}

      <div className="flex flex-wrap items-center justify-between gap-2 border-t border-radar-border/40 pt-3">
        <button
          type="button"
          onClick={() => setShowClearConfirm(true)}
          disabled={env.state.assets.length === 0}
          className="focus-ring inline-flex items-center gap-1 rounded-md border border-radar-border bg-radar-panel2 px-2 py-1 text-[11px] text-radar-muted hover:border-radar-warn/40 hover:text-radar-warn disabled:opacity-50"
          data-testid="environment-clear-button"
        >
          <Trash2 className="h-3 w-3" />
          Clear all environment data
        </button>
      </div>

      {showClearConfirm && (
        <div className="rounded-md border border-radar-warn/40 bg-radar-warn/5 p-3 text-[12px] text-radar-warn" role="alert" aria-live="polite" data-testid="environment-clear-warning">
          <p>
            This removes every asset, inventory, component, correlation, and review record from your local environment. This is separate from clearing the workspace.
          </p>
          <div className="mt-2 flex flex-wrap items-center gap-2">
            <button
              type="button"
              onClick={handleClear}
              className="focus-ring inline-flex items-center gap-1 rounded-md border border-radar-warn/40 bg-radar-warn/10 px-2.5 py-1.5 text-xs text-radar-warn"
              data-testid="environment-clear-confirm"
            >
              Confirm clear
            </button>
            <button
              type="button"
              onClick={() => setShowClearConfirm(false)}
              className="focus-ring inline-flex items-center gap-1 rounded-md border border-radar-border bg-radar-panel2 px-2.5 py-1.5 text-xs text-radar-muted"
            >
              Cancel
            </button>
          </div>
        </div>
      )}

      {showCreateAsset && (
        <AssetDialog
          title="New asset"
          onClose={() => setShowCreateAsset(false)}
          onSubmit={async (args) => {
            const r = await env.createAsset(args);
            if (r.ok) setShowCreateAsset(false);
            return r;
          }}
        />
      )}
      {editingAsset && (
        <AssetDialog
          title="Edit asset"
          initial={editingAsset}
          onClose={() => setEditingAsset(null)}
          onSubmit={async (args) => {
            const r = await env.updateAsset(editingAsset.assetId, args);
            if (r.ok) setEditingAsset(null);
            return r;
          }}
        />
      )}
      {showImport && (
        <InventoryImportDialog onClose={() => setShowImport(false)} assets={liveAssets} />
      )}
    </section>
  );
}

function CountCard({ icon, label, value }: { icon: React.ReactNode; label: string; value: number }) {
  return (
    <div className="rounded-md border border-radar-border bg-radar-panel2/30 p-2 text-[11px]">
      <div className="flex items-center gap-1 text-radar-muted">{icon}<span>{label}</span></div>
      <div className="mt-1 text-base font-semibold text-radar-text">{value}</div>
    </div>
  );
}
