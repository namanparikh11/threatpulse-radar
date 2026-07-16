/**
 * V6.6 — Environment schema (types).
 */
export const ASSET_SCHEMA_VERSION: '1.0.0';
export const COMPONENT_SCHEMA_VERSION: '1.0.0';
export const CORRELATION_SCHEMA_VERSION: '1.0.0';
export const REVIEW_SCHEMA_VERSION: '1.0.0';

export const ASSET_ENVIRONMENTS: readonly string[];
export const ASSET_TYPES: readonly string[];
export const ASSET_CRITICALITIES: readonly string[];
export const COMPONENT_TYPES: readonly string[];
export const SUPPORTED_SBOM_FORMATS: readonly string[];
export const CORRELATION_STATES: readonly string[];
export const REVIEW_STATUSES: readonly string[];

export const ASSET_LIMITS: {
  MAX_IMPORT_BYTES: number;
  MAX_COMPONENTS_PER_IMPORT: number;
  WARNING_COMPONENT_COUNT: number;
  MAX_ASSETS: number;
  MAX_ASSET_TAGS: number;
  MAX_TAG_CHARS: number;
  MAX_ASSET_NAME_CHARS: number;
  MAX_ASSET_DESCRIPTION_CHARS: number;
  MAX_OWNER_LABEL_CHARS: number;
  MAX_INVENTORY_SNAPSHOTS_PER_ASSET: number;
  MAX_CORRELATION_REVIEWS: number;
  MAX_COMPONENT_NAME_CHARS: number;
  MAX_COMPONENT_VERSION_CHARS: number;
  MAX_COMPONENT_PATH_CHARS: number;
  MAX_HASH_CHARS: number;
  MAX_REVIEW_NOTE_CHARS: number;
  MAX_SUPPLIER_CHARS: number;
};

export interface AssetInput {
  assetId: string;
  name: string;
  description: string;
  environment: 'production' | 'staging' | 'development' | 'test' | 'personal' | 'unknown';
  assetType: 'server' | 'workstation' | 'container' | 'application' | 'repository' | 'mobile' | 'network-device' | 'other';
  localCriticality: 'none' | 'low' | 'medium' | 'high' | 'critical';
  ownerLabel: string;
  tags: string[];
  schemaVersion: string;
  createdAt: string;
  updatedAt: string;
  archived: boolean;
  latestInventoryId: string | null;
}

export interface ComponentInput {
  componentId: string;
  assetId: string;
  inventoryId: string;
  name: string;
  version: string | null;
  ecosystem: string | null;
  namespace: string | null;
  packageUrl: string | null;
  cpe: string | null;
  supplier: string | null;
  componentType: string;
  hashes: string[];
  sourcePath: string | null;
  normalizedIdentity: Record<string, any>;
  schemaVersion: string;
  createdAt: string;
}

export interface InventoryInput {
  inventoryId: string;
  assetId: string;
  sourceFormat: 'cyclonedx-json' | 'spdx-json' | 'threatpulse-inventory-json' | 'csv';
  sourceVersion: string | null;
  importedAt: string;
  fileName: string;
  componentCount: number;
  checksum: string;
  warnings: string[];
  metadata: Record<string, any>;
  schemaVersion: string;
}

export interface CorrelationInput {
  correlationId: string;
  assetId: string;
  inventoryId: string;
  componentId: string;
  cveId: string;
  state: string;
  providerSources: string[];
  matchedPackageIdentity: Record<string, any>;
  importedVersion: string | null;
  evaluatedRanges: any[];
  evidence: any[];
  limitations: string[];
  generatedAt: string;
  publicIntelligenceVersion: string | null;
  publicProjectionSchemaVersion: string | null;
  correlationSchemaVersion: string;
}

export interface ReviewInput {
  correlationId: string;
  reviewStatus: string;
  note: string;
  updatedAt: string;
  revision: number;
  mutationId: string;
  schemaVersion: string;
}

export interface ValidateResult<T> { ok: true; value: T }
export interface ValidateError { ok: false; reason: string }

export function validateAsset(input: any): ValidateResult<AssetInput> | ValidateError;
export function validateComponent(input: any): ValidateResult<ComponentInput> | ValidateError;
export function validateInventory(input: any): ValidateResult<InventoryInput> | ValidateError;
export function validateCorrelation(input: any): ValidateResult<CorrelationInput> | ValidateError;
export function validateReview(input: any): ValidateResult<ReviewInput> | ValidateError;
