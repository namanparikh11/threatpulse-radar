/**
 * V6.5 — Exporter dispatcher (types).
 */
export type ExportFormat = 'markdown' | 'html' | 'print' | 'json';

export function listExportFormats(): ExportFormat[];

export function isExportFormatSupported(format: string): boolean;

export interface ExportResult {
  filename: string;
  mimeType: string;
  body: string;
}

export function exportReport(report: any, format: ExportFormat): ExportResult;

export function renderMarkdown(report: any): string;
export function renderHtml(report: any): string;
export function renderPrintHtml(report: any): string;
export function renderJson(report: any): string;
