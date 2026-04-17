import * as core from "@actions/core";
import * as exec from "@actions/exec";
import * as tc from "@actions/tool-cache";
import * as crypto from "crypto";
import * as fs from "fs";
import * as os from "os";
import * as path from "path";
import * as process from "process";
import { verify as sigstoreVerify } from "sigstore";
import type { Bundle } from "sigstore";

export type { WitnessArch, WitnessParams } from "./types";
import type { WitnessArch, WitnessParams } from "./types";



export function getArch(): WitnessArch {
  return process.arch === "arm64" ? "arm64" : "amd64";
}

export function getArtifactFilename(
  version: string,
  platform: NodeJS.Platform,
  arch: WitnessArch
): string {
  let osName: string;
  if (platform === "win32") {
    osName = "windows";
  } else if (platform === "darwin") {
    osName = "darwin";
  } else {
    osName = "linux";
  }
  return `witness_${version}_${osName}_${arch}.tar.gz`;
}

export function getDownloadURL(
  version: string,
  platform: NodeJS.Platform,
  arch: WitnessArch
): string {
  const base = `https://github.com/in-toto/witness/releases/download/v${version}`;
  return `${base}/${getArtifactFilename(version, platform, arch)}`;
}

export function getVerificationURLs(
  version: string,
  platform: NodeJS.Platform,
  arch: WitnessArch
): { certURL: string; sigURL: string } {
  const base = `https://github.com/in-toto/witness/releases/download/v${version}`;
  const filename = getArtifactFilename(version, platform, arch);
  return {
    certURL: `${base}/${filename}.pem`,
    sigURL: `${base}/${filename}.sig`,
  };
}

export function computeSha256File(filePath: string): string {
  const data = fs.readFileSync(filePath);
  return crypto.createHash("sha256").update(data).digest("hex");
}

export async function verifyWitnessSignature(
  archivePath: string,
  certPem: string,
  sigBase64: string,
  certIdentity: string,
  certIssuer: string
): Promise<void> {
  const archiveBytes = fs.readFileSync(archivePath) as Buffer;
  const digest = crypto.createHash("sha256").update(archiveBytes).digest();

  // Strip PEM headers/footers and whitespace to get raw DER base64
  const certBase64 = certPem.replace(/-----[A-Z ]+-----/g, "").replace(/\s/g, "");

  const bundle: Bundle = {
    mediaType: "application/vnd.dev.sigstore.bundle+json;version=0.1",
    verificationMaterial: {
      x509CertificateChain: {
        certificates: [{ rawBytes: certBase64 }],
      },
      // Required by OneOf discriminant -- absent alternatives must be undefined
      certificate: undefined,
      publicKey: undefined,
      tlogEntries: [],
      timestampVerificationData: undefined,
    },
    messageSignature: {
      messageDigest: {
        algorithm: "SHA2_256",
        digest: digest.toString("base64"),
      },
      signature: sigBase64,
    },
    // Required by OneOf discriminant
    dsseEnvelope: undefined,
  };

  await sigstoreVerify(bundle, archiveBytes, {
    certificateIdentityURI: certIdentity,
    certificateIssuer: certIssuer,
    // tlog and CT log entries are not included in the legacy cosign artifact format;
    // cert chain and identity are verified via TUF.
    tlogThreshold: 0,
    ctLogThreshold: 0,
  });
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

  if (witnessPath) {
    const sidecarPath = path.join(witnessPath, "witness.sha256");
    if (!fs.existsSync(sidecarPath)) {
      // Cache entry predates SHA verification -- treat as miss and re-download
      core.info("Cached witness has no SHA sidecar, re-downloading for verification");
      witnessPath = "";
    } else {
      const storedSha = fs.readFileSync(sidecarPath, { encoding: "utf-8" }).trim();
      const actualSha = computeSha256File(path.join(witnessPath, "witness"));
      if (storedSha !== actualSha) {
        core.setFailed(
          `Cached witness binary failed SHA256 verification. ` +
          `Expected: ${storedSha}, Got: ${actualSha}. ` +
          `The runner cache may have been tampered with.`
        );
        return;
      }
      core.info("Cached witness binary SHA256 verified");
    }
  }

  if (!witnessPath) {
    const certIdentity = core.getInput("cosign-certificate-identity") ||
      `https://github.com/in-toto/witness/.github/workflows/release.yml@refs/tags/v${version}`;
    const certIssuer = core.getInput("cosign-certificate-oidc-issuer") ||
      "https://token.actions.githubusercontent.com";

    const arch = getArch();
    const downloadURL = getDownloadURL(version, process.platform, arch);
    const { certURL, sigURL } = getVerificationURLs(version, process.platform, arch);

    core.info("Witness not found in cache, downloading");
    core.info(`Downloading witness from: ${downloadURL}`);

    const [witnessDL, certPath, sigPath] = await Promise.all([
      tc.downloadTool(downloadURL),
      tc.downloadTool(certURL),
      tc.downloadTool(sigURL),
    ]);

    core.info("Verifying witness archive with Sigstore");
    const certPem = fs.readFileSync(certPath, { encoding: "utf-8" });
    const sigBase64 = fs.readFileSync(sigPath, { encoding: "utf-8" }).trim();
    try {
      await verifyWitnessSignature(witnessDL, certPem, sigBase64, certIdentity, certIssuer);
    } catch (err) {
      core.setFailed(`Sigstore verification failed: ${(err as Error).message}`);
      return;
    }
    core.info("Sigstore verification passed");

    if (!fs.existsSync(witnessInstallDir)) {
      core.info(`Creating witness install directory: ${witnessInstallDir}`);
      fs.mkdirSync(witnessInstallDir, { recursive: true });
    }

    core.info(`Extracting witness to: ${witnessInstallDir}`);
    const extractedDir = await tc.extractTar(witnessDL, witnessInstallDir);

    const binarySha = computeSha256File(path.join(extractedDir, "witness"));
    fs.writeFileSync(path.join(extractedDir, "witness.sha256"), binarySha);

    witnessPath = await tc.cacheDir(extractedDir, "witness", version);
    core.info(`Witness cached at: ${witnessPath}`);
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
