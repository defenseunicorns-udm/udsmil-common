export type WitnessArch = "amd64" | "arm64";

export interface WitnessParams {
  step: string;
  attestations: string[];
  certificate: string;
  enableArchivista: boolean;
  archivistaServer: string;
  archivistaHeaders: string[];
  fulcio: string;
  fulcioOidcClientId: string;
  fulcioOidcIssuer: string;
  fulcioToken: string;
  intermediates: string[];
  key: string;
  outfile: string;
  productExcludeGlob: string;
  productIncludeGlob: string;
  spiffeSocket: string;
  timestampServers: string[];
  trace: string;
  exportLink: boolean;
  exportSBOM: boolean;
  exportSLSA: boolean;
  mavenPOM: string;
}
