/**
 * V6.1 — Public OSV projection types.
 *
 * The OSV section in the DetailDrawer renders the public
 * OSV projection for a single CVE. The data is fetched
 * via the `view=osv` query mode on the dataset function
 * and attached to the `vuln.osv` field on the
 * Vulnerability.
 *
 * The schema is documented in
 * `schemas/osv-shard-v1.schema.json`. Per-record field
 * caps and truncation metadata are part of the public
 * contract.
 */

export type OsvEvent = {
  introduced?: string;
  fixed?: string;
  last_affected?: string;
  limit?: string;
};

export type OsvRange = {
  type: string;
  events: OsvEvent[];
  databaseSpecific: Record<string, unknown> | null;
  repo: string | null;
};

export type OsvAffectedPackage = {
  ecosystem: string;
  name: string;
  purl: string | null;
  ranges: OsvRange[];
  versions: string[];
  ecosystemSpecific: Record<string, unknown> | null;
  truncation: {
    versionsRemoved: number;
    rangesRemoved: number;
    eventsTruncated: number;
  };
};

export type OsvPublicRecord = {
  osvId: string;
  sourceDatabase: string;
  aliases: string[];
  modifiedAt: string | null;
  publishedAt: string | null;
  withdrawn: boolean;
  references: { type: string; url: string }[];
  severities: { type: string; score: string }[];
  affectedPackages: OsvAffectedPackage[];
  truncation: {
    aliasesRemoved: number;
    referencesRemoved: number;
    packagesRemoved: number;
  };
};

export type OsvPublicContext = {
  records: OsvPublicRecord[];
  truncation: { recordsRemoved: number };
};
