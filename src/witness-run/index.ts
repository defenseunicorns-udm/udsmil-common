import * as core from "@actions/core";
import * as exec from "@actions/exec";
import * as tc from "@actions/tool-cache";
import * as fs from "fs";
import * as os from "os";
import * as path from "path";
import * as process from "process";

export type { WitnessArch, WitnessParams } from "./types";
import type { WitnessArch, WitnessParams } from "./types";



export function getArch(): WitnessArch {
  return process.arch === "arm64" ? "arm64" : "amd64";
}

export function getDownloadURL(
  version: string,
  platform: NodeJS.Platform,
  arch: WitnessArch
): string {
  if (platform === "win32") {
    return `https://github.com/in-toto/witness/releases/download/v${version}/witness_${version}_windows_${arch}.zip`;
  }
  const os = platform === "darwin" ? "darwin" : "linux";
  return `https://github.com/in-toto/witness/releases/download/v${version}/witness_${version}_${os}_${arch}.tar.gz`;
}

export function buildWitnessArgs(params: WitnessParams): string[] {
  const cmd: string[] = ["run"];

  params.attestations.forEach((a) => {
    const trimmed = a.trim();
    if (trimmed) cmd.push(`-a=${trimmed}`);
  });

  if (params.exportLink) cmd.push("--attestor-link-export");
  if (params.exportSBOM) cmd.push("--attestor-sbom-export");
  if (params.exportSLSA) cmd.push("--attestor-slsa-export");
  if (params.mavenPOM) cmd.push(`--attestor-maven-pom-path=${params.mavenPOM}`);

  if (params.certificate) cmd.push(`--certificate=${params.certificate}`);
  if (params.enableArchivista) cmd.push(`--enable-archivista=${params.enableArchivista}`);
  if (params.archivistaServer) cmd.push(`--archivista-server=${params.archivistaServer}`);

  params.archivistaHeaders.forEach((h) => {
    const trimmed = h.trim();
    if (trimmed) cmd.push(`--archivista-headers=${trimmed}`);
  });

  if (params.fulcio) cmd.push(`--signer-fulcio-url=${params.fulcio}`);
  if (params.fulcioOidcClientId) cmd.push(`--signer-fulcio-oidc-client-id=${params.fulcioOidcClientId}`);
  if (params.fulcioOidcIssuer) cmd.push(`--signer-fulcio-oidc-issuer=${params.fulcioOidcIssuer}`);
  if (params.fulcioToken) cmd.push(`--signer-fulcio-token=${params.fulcioToken}`);

  params.intermediates.forEach((i) => {
    const trimmed = i.trim();
    if (trimmed) cmd.push(`-i=${trimmed}`);
  });

  if (params.key) cmd.push(`--key=${params.key}`);
  if (params.productExcludeGlob) cmd.push(`--attestor-product-exclude-glob=${params.productExcludeGlob}`);
  if (params.productIncludeGlob) cmd.push(`--attestor-product-include-glob=${params.productIncludeGlob}`);
  if (params.spiffeSocket) cmd.push(`--spiffe-socket=${params.spiffeSocket}`);
  if (params.step) cmd.push(`-s=${params.step}`);

  params.timestampServers.forEach((ts) => {
    const trimmed = ts.trim();
    if (trimmed) cmd.push(`--timestamp-servers=${trimmed}`);
  });

  if (params.trace) cmd.push(`--trace=${params.trace}`);
  cmd.push(`--outfile=${params.outfile}`);

  return cmd;
}

export function extractDesiredGitOIDs(output: string): string[] {
  const desiredSubstring = "Stored in archivista as ";
  const results: string[] = [];

  for (const line of output.split("\n")) {
    if (line.indexOf(desiredSubstring) === -1) continue;
    core.debug(`Checking line for GitOID: ${line}`);
    const match = line.match(/[0-9a-fA-F]{64}/);
    if (match) {
      core.debug(`Found GitOID: ${match[0]}`);
      results.push(match[0]);
    }
  }

  return results;
}

function escapeMd(s: string): string {
  return s.replace(/\|/g, "\\|").replace(/</g, "&lt;").replace(/>/g, "&gt;");
}

async function run(): Promise<void> {
  const workspace = process.env["GITHUB_WORKSPACE"];
  if (!workspace) {
    core.setFailed("GITHUB_WORKSPACE environment variable is not set");
    return;
  }

  const stepSummaryPath = process.env["GITHUB_STEP_SUMMARY"];
  if (!stepSummaryPath) {
    core.setFailed("GITHUB_STEP_SUMMARY environment variable is not set");
    return;
  }

  const version = core.getInput("version");
  if (!/^\d+\.\d+\.\d+$/.test(version)) {
    core.setFailed(`Invalid version format: "${version}". Expected MAJOR.MINOR.PATCH with no v prefix.`);
    return;
  }

  const workingdir = core.getInput("workingdir") || "";
  const fullWorkspacePath = path.resolve(workspace, workingdir);
  if (!fullWorkspacePath.startsWith(path.resolve(workspace))) {
    core.setFailed(`workingdir "${workingdir}" resolves outside GITHUB_WORKSPACE`);
    return;
  }

  const command = core.getInput("command");
  if (!command.trim()) {
    core.setFailed("command input is required and cannot be empty");
    return;
  }
  const commandArray = command.match(/(?:[^\s"]+|"[^"]*")+/g);
  if (!commandArray) {
    core.setFailed("command input could not be parsed into arguments");
    return;
  }

  const witnessInstallDir = core.getInput("witness-install-dir") || fullWorkspacePath;

  let witnessPath = tc.find("witness", version);
  core.info(`Cached Witness path: ${witnessPath || "(not found)"}`);

  if (!witnessPath) {
    core.info("Witness not found in cache, downloading");
    const arch = getArch();
    const downloadURL = getDownloadURL(version, process.platform, arch);
    core.info(`Downloading witness from: ${downloadURL}`);
    const witnessDL = await tc.downloadTool(downloadURL);

    if (!fs.existsSync(witnessInstallDir)) {
      core.info(`Creating witness install directory: ${witnessInstallDir}`);
      fs.mkdirSync(witnessInstallDir, { recursive: true });
    }

    core.info(`Extracting witness to: ${witnessInstallDir}`);
    if (process.platform === "win32") {
      witnessPath = await tc.extractZip(witnessDL, witnessInstallDir);
    } else {
      witnessPath = await tc.extractTar(witnessDL, witnessInstallDir);
    }

    const cachedPath = await tc.cacheFile(
      path.join(witnessPath, "witness"),
      "witness",
      "witness",
      version
    );
    core.info(`Witness cached at: ${cachedPath}`);
  }

  core.addPath(witnessPath);

  const step = core.getInput("step");
  const archivistaServer = core.getInput("archivista-server");
  const archivistaHeaders = core.getInput("archivista-headers").split(/\r|\n/);
  const attestations = core.getInput("attestations").split(" ");
  const certificate = core.getInput("certificate");
  const enableArchivista = core.getInput("enable-archivista") === "true";
  let fulcio = core.getInput("fulcio");
  let fulcioOidcClientId = core.getInput("fulcio-oidc-client-id");
  let fulcioOidcIssuer = core.getInput("fulcio-oidc-issuer");
  const fulcioToken = core.getInput("fulcio-token");
  const intermediates = core.getInput("intermediates").split(" ");
  const key = core.getInput("key");
  const outfileInput = core.getInput("outfile");
  const outfile = outfileInput || path.join(os.tmpdir(), `${step}-attestation.json`);
  const productExcludeGlob = core.getInput("product-exclude-glob");
  const productIncludeGlob = core.getInput("product-include-glob");
  const spiffeSocket = core.getInput("spiffe-socket");
  let timestampServers = core.getInput("timestamp-servers");
  const trace = core.getInput("trace");
  const enableSigstore = core.getInput("enable-sigstore") === "true";

  if (enableSigstore) {
    fulcio = fulcio || "https://fulcio.sigstore.dev";
    fulcioOidcClientId = fulcioOidcClientId || "sigstore";
    fulcioOidcIssuer = fulcioOidcIssuer || "https://oauth2.sigstore.dev/auth";
    timestampServers = timestampServers || "https://timestamp.sigstore.dev/api/v1/timestamp";
  }

  const exportLink = core.getInput("attestor-link-export") === "true";
  const exportSBOM = core.getInput("attestor-sbom-export") === "true";
  const exportSLSA = core.getInput("attestor-slsa-export") === "true";
  const mavenPOM = core.getInput("attestor-maven-pom-path");

  const cmd = buildWitnessArgs({
    step,
    attestations,
    certificate,
    enableArchivista,
    archivistaServer,
    archivistaHeaders,
    fulcio,
    fulcioOidcClientId,
    fulcioOidcIssuer,
    fulcioToken,
    intermediates,
    key,
    outfile,
    productExcludeGlob,
    productIncludeGlob,
    spiffeSocket,
    timestampServers: timestampServers ? timestampServers.split(" ") : [],
    trace,
    exportLink,
    exportSBOM,
    exportSLSA,
    mavenPOM,
  });

  core.info(`Running witness in directory: ${fullWorkspacePath}`);

  let output = "";
  await exec.exec("witness", [...cmd, "--", ...commandArray], {
    cwd: fullWorkspacePath,
    listeners: {
      stdout: (data: Buffer) => {
        output += data.toString();
      },
      stderr: (data: Buffer) => {
        output += data.toString();
      },
    },
  });

  const gitOIDs = extractDesiredGitOIDs(output);
  core.setOutput("git_oid", gitOIDs.join(","));

  if (gitOIDs.length > 0) {
    const summaryHeader = `
## Attestations Created
| Step | Attestors Run | Attestation GitOID
| --- | --- | --- |
`;
    const summaryFile = fs.readFileSync(stepSummaryPath, { encoding: "utf-8" });
    if (!summaryFile.includes(summaryHeader.trim())) {
      fs.appendFileSync(stepSummaryPath, summaryHeader);
    }

    for (const gitOID of gitOIDs) {
      const artifactURL = `${archivistaServer}/download/${gitOID}`;
      const tableRow = `| ${escapeMd(step)} | ${attestations.map(escapeMd).join(", ")} | [${gitOID}](${artifactURL}) |\n`;
      fs.appendFileSync(stepSummaryPath, tableRow);
    }
  }
}

export { run };

// Only execute when this file is the entry point (not during tests)
if (require.main === module) {
  run().catch((err: Error) => core.setFailed(err.message));
}
