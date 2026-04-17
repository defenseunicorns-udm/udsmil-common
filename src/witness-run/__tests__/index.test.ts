import * as core from "@actions/core";
import * as exec from "@actions/exec";
import * as tc from "@actions/tool-cache";
import * as fs from "fs";

jest.mock("@actions/core");
jest.mock("@actions/exec");
jest.mock("@actions/tool-cache");
// Partial mock: preserve fs.promises (used by @actions/core internals) while
// mocking only the sync functions called by index.ts.
jest.mock("fs", () => {
  const actual = jest.requireActual<typeof import("fs")>("fs");
  return {
    ...actual,
    readFileSync: jest.fn(),
    appendFileSync: jest.fn(),
    existsSync: jest.fn(),
    mkdirSync: jest.fn(),
  };
});

const mockedCore = jest.mocked(core);
const mockedExec = jest.mocked(exec);
const mockedTc = jest.mocked(tc);
const mockedFs = jest.mocked(fs);

import {
  extractDesiredGitOIDs,
  buildWitnessArgs,
  getDownloadURL,
  getArch,
  run,
  WitnessParams,
} from "../index";

// WitnessArch is only used as a type; TypeScript strips it at compile time.
// eslint-disable-next-line @typescript-eslint/no-unused-vars
type _WitnessArch = import("../index").WitnessArch;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

const FAKE_WORKSPACE = "/workspace";
const FAKE_SUMMARY = "/tmp/summary.md";

function baseParams(overrides: Partial<WitnessParams> = {}): WitnessParams {
  return {
    step: "test-step",
    attestations: ["environment", "git"],
    certificate: "",
    enableArchivista: false,
    archivistaServer: "",
    archivistaHeaders: [],
    fulcio: "",
    fulcioOidcClientId: "",
    fulcioOidcIssuer: "",
    fulcioToken: "",
    intermediates: [],
    key: "",
    outfile: "/tmp/test-step-attestation.json",
    productExcludeGlob: "",
    productIncludeGlob: "",
    spiffeSocket: "",
    timestampServers: [],
    trace: "",
    exportLink: false,
    exportSBOM: false,
    exportSLSA: false,
    mavenPOM: "",
    ...overrides,
  };
}

function makeInputMap(overrides: Record<string, string> = {}): Record<string, string> {
  return {
    version: "0.9.2",
    workingdir: "",
    command: "echo hello",
    step: "lint",
    "enable-archivista": "false",
    "enable-sigstore": "false",
    attestations: "environment git github",
    "archivista-server": "https://archivista.testifysec.io",
    "archivista-headers": "",
    certificate: "",
    fulcio: "",
    "fulcio-oidc-client-id": "",
    "fulcio-oidc-issuer": "",
    "fulcio-token": "",
    intermediates: "",
    key: "",
    outfile: "",
    "product-exclude-glob": "",
    "product-include-glob": "",
    "spiffe-socket": "",
    "timestamp-servers": "",
    trace: "",
    "attestor-link-export": "false",
    "attestor-sbom-export": "false",
    "attestor-slsa-export": "false",
    "attestor-maven-pom-path": "",
    "witness-install-dir": "",
    ...overrides,
  };
}

function setupRunMocks(inputOverrides: Record<string, string> = {}): void {
  const inputs = makeInputMap(inputOverrides);
  mockedCore.getInput.mockImplementation((name: string) => inputs[name] ?? "");
  mockedTc.find.mockReturnValue("/cached/witness");
  mockedCore.addPath.mockImplementation(() => undefined);
  mockedExec.exec.mockResolvedValue(0);
  mockedFs.readFileSync.mockReturnValue("");
  mockedFs.existsSync.mockReturnValue(true);
  mockedFs.appendFileSync.mockImplementation(() => undefined);
}

// ---------------------------------------------------------------------------
// Group 1: extractDesiredGitOIDs (pure function, no mocks)
// ---------------------------------------------------------------------------

describe("extractDesiredGitOIDs", () => {
  // Silence core.debug inside the function during these tests
  beforeAll(() => {
    mockedCore.debug.mockImplementation(() => undefined);
  });

  it("returns empty array for empty string", () => {
    expect(extractDesiredGitOIDs("")).toEqual([]);
  });

  it("returns empty array when no matching line exists", () => {
    expect(extractDesiredGitOIDs("some random output\nanother line")).toEqual([]);
  });

  it("extracts a single 64-char hex GitOID", () => {
    const hex = "a".repeat(64);
    const output = `some prefix\nStored in archivista as ${hex}\ntrailing line`;
    expect(extractDesiredGitOIDs(output)).toEqual([hex]);
  });

  it("extracts two GitOIDs from two matching lines", () => {
    const hex1 = "a".repeat(64);
    const hex2 = "b".repeat(64);
    const output = `Stored in archivista as ${hex1}\nother\nStored in archivista as ${hex2}`;
    expect(extractDesiredGitOIDs(output)).toEqual([hex1, hex2]);
  });

  it("ignores a line with the prefix but no hex", () => {
    expect(extractDesiredGitOIDs("Stored in archivista as not-a-hash")).toEqual([]);
  });

  it("ignores a 63-char hex (too short)", () => {
    const shortHex = "a".repeat(63);
    expect(extractDesiredGitOIDs(`Stored in archivista as ${shortHex}`)).toEqual([]);
  });

  it("ignores lines that do not contain the required substring", () => {
    const hex = "c".repeat(64);
    expect(extractDesiredGitOIDs(`unrelated line with ${hex}`)).toEqual([]);
  });
});

// ---------------------------------------------------------------------------
// Group 2: buildWitnessArgs (pure function, flag assembly)
// ---------------------------------------------------------------------------

describe("buildWitnessArgs", () => {
  it("minimal params produces run, step flag, and outfile", () => {
    const args = buildWitnessArgs(baseParams({ attestations: [] }));
    expect(args[0]).toBe("run");
    expect(args).toContain("-s=test-step");
    expect(args).toContain("--outfile=/tmp/test-step-attestation.json");
  });

  it("attestations produce -a= flags and skip empty entries", () => {
    const args = buildWitnessArgs(baseParams({ attestations: ["environment", "", "git"] }));
    expect(args).toContain("-a=environment");
    expect(args).toContain("-a=git");
    expect(args.filter((a) => a === "-a=")).toHaveLength(0);
  });

  it("exportLink produces --attestor-link-export flag", () => {
    const args = buildWitnessArgs(baseParams({ exportLink: true }));
    expect(args).toContain("--attestor-link-export");
  });

  it("exportSBOM produces --attestor-sbom-export flag", () => {
    const args = buildWitnessArgs(baseParams({ exportSBOM: true }));
    expect(args).toContain("--attestor-sbom-export");
  });

  it("exportSLSA produces --attestor-slsa-export flag", () => {
    const args = buildWitnessArgs(baseParams({ exportSLSA: true }));
    expect(args).toContain("--attestor-slsa-export");
  });

  it("enableArchivista with server produces correct flags", () => {
    const args = buildWitnessArgs(
      baseParams({ enableArchivista: true, archivistaServer: "https://arch.example.com" })
    );
    expect(args).toContain("--enable-archivista=true");
    expect(args).toContain("--archivista-server=https://arch.example.com");
  });

  it("archivistaHeaders produces individual flags with no embedded quotes", () => {
    const args = buildWitnessArgs(
      baseParams({ archivistaHeaders: ["Authorization: Bearer tok", "X-Org: myorg"] })
    );
    expect(args).toContain("--archivista-headers=Authorization: Bearer tok");
    expect(args).toContain("--archivista-headers=X-Org: myorg");
    // Verify no embedded quote characters in the flag values
    const headerArgs = args.filter((a) => a.startsWith("--archivista-headers="));
    headerArgs.forEach((a) => expect(a).not.toContain('"'));
  });

  it("archivistaHeaders skips empty and whitespace-only entries", () => {
    const args = buildWitnessArgs(baseParams({ archivistaHeaders: ["  ", ""] }));
    expect(args.some((a) => a.startsWith("--archivista-headers="))).toBe(false);
  });

  it("intermediates produce -i= flags", () => {
    const args = buildWitnessArgs(baseParams({ intermediates: ["cert1.pem", "cert2.pem"] }));
    expect(args).toContain("-i=cert1.pem");
    expect(args).toContain("-i=cert2.pem");
  });

  it("timestampServers produce --timestamp-servers= flags", () => {
    const args = buildWitnessArgs(
      baseParams({ timestampServers: ["https://ts1.example.com", "https://ts2.example.com"] })
    );
    expect(args).toContain("--timestamp-servers=https://ts1.example.com");
    expect(args).toContain("--timestamp-servers=https://ts2.example.com");
  });

  it("fulcio params produce signer flags", () => {
    const args = buildWitnessArgs(
      baseParams({
        fulcio: "https://fulcio.sigstore.dev",
        fulcioOidcClientId: "sigstore",
        fulcioOidcIssuer: "https://oauth2.sigstore.dev/auth",
      })
    );
    expect(args).toContain("--signer-fulcio-url=https://fulcio.sigstore.dev");
    expect(args).toContain("--signer-fulcio-oidc-client-id=sigstore");
    expect(args).toContain("--signer-fulcio-oidc-issuer=https://oauth2.sigstore.dev/auth");
  });

  it("empty optional fields produce no extra flags", () => {
    const args = buildWitnessArgs(baseParams());
    expect(args.some((a) => a.startsWith("--certificate="))).toBe(false);
    expect(args.some((a) => a.startsWith("--key="))).toBe(false);
    expect(args.some((a) => a.startsWith("--spiffe-socket="))).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// Group 3: getDownloadURL
// ---------------------------------------------------------------------------

describe("getDownloadURL", () => {
  it("linux amd64 produces linux tar.gz URL", () => {
    const url = getDownloadURL("0.9.2", "linux", "amd64");
    expect(url).toContain("linux_amd64.tar.gz");
    expect(url).toContain("v0.9.2");
    expect(url).toContain("witness_0.9.2");
  });

  it("linux arm64 produces linux arm64 tar.gz URL", () => {
    const url = getDownloadURL("0.9.2", "linux", "arm64");
    expect(url).toContain("linux_arm64.tar.gz");
  });

  it("darwin amd64 produces darwin tar.gz URL", () => {
    const url = getDownloadURL("0.9.2", "darwin", "amd64");
    expect(url).toContain("darwin_amd64.tar.gz");
  });

  it("darwin arm64 produces darwin arm64 tar.gz URL", () => {
    const url = getDownloadURL("0.9.2", "darwin", "arm64");
    expect(url).toContain("darwin_arm64.tar.gz");
  });

  it("win32 produces windows zip URL", () => {
    const url = getDownloadURL("0.9.2", "win32", "amd64");
    expect(url).toContain("windows_amd64.zip");
    expect(url).not.toContain(".tar.gz");
  });
});

// ---------------------------------------------------------------------------
// Group 4: getArch
// ---------------------------------------------------------------------------

describe("getArch", () => {
  const originalArch = process.arch;

  afterEach(() => {
    Object.defineProperty(process, "arch", { value: originalArch, configurable: true });
  });

  it("returns arm64 on arm64 machines", () => {
    Object.defineProperty(process, "arch", { value: "arm64", configurable: true });
    expect(getArch()).toBe("arm64");
  });

  it("returns amd64 on x64 machines", () => {
    Object.defineProperty(process, "arch", { value: "x64", configurable: true });
    expect(getArch()).toBe("amd64");
  });

  it("returns amd64 on any unrecognized arch", () => {
    Object.defineProperty(process, "arch", { value: "mips", configurable: true });
    expect(getArch()).toBe("amd64");
  });
});

// ---------------------------------------------------------------------------
// Group 5: run() -- env var validation
// ---------------------------------------------------------------------------

describe("run() - env var validation", () => {
  const originalWorkspace = process.env["GITHUB_WORKSPACE"];
  const originalSummary = process.env["GITHUB_STEP_SUMMARY"];

  beforeEach(() => {
    process.env["GITHUB_WORKSPACE"] = FAKE_WORKSPACE;
    process.env["GITHUB_STEP_SUMMARY"] = FAKE_SUMMARY;
  });

  afterEach(() => {
    if (originalWorkspace === undefined) {
      delete process.env["GITHUB_WORKSPACE"];
    } else {
      process.env["GITHUB_WORKSPACE"] = originalWorkspace;
    }
    if (originalSummary === undefined) {
      delete process.env["GITHUB_STEP_SUMMARY"];
    } else {
      process.env["GITHUB_STEP_SUMMARY"] = originalSummary;
    }
  });

  it("calls setFailed when GITHUB_WORKSPACE is missing", async () => {
    delete process.env["GITHUB_WORKSPACE"];
    setupRunMocks();
    await run();
    expect(mockedCore.setFailed).toHaveBeenCalledWith(
      expect.stringContaining("GITHUB_WORKSPACE")
    );
  });

  it("calls setFailed when GITHUB_STEP_SUMMARY is missing", async () => {
    delete process.env["GITHUB_STEP_SUMMARY"];
    setupRunMocks();
    await run();
    expect(mockedCore.setFailed).toHaveBeenCalledWith(
      expect.stringContaining("GITHUB_STEP_SUMMARY")
    );
  });
});

// ---------------------------------------------------------------------------
// Group 6: run() -- version validation
// ---------------------------------------------------------------------------

describe("run() - version validation", () => {
  beforeEach(() => {
    process.env["GITHUB_WORKSPACE"] = FAKE_WORKSPACE;
    process.env["GITHUB_STEP_SUMMARY"] = FAKE_SUMMARY;
  });

  afterEach(() => {
    delete process.env["GITHUB_WORKSPACE"];
    delete process.env["GITHUB_STEP_SUMMARY"];
  });

  const invalidVersions = ["v0.6.0", "0.6", "latest", "1.2.3.4", "1.2.3-rc1", ""];

  invalidVersions.forEach((v) => {
    it(`rejects version "${v}"`, async () => {
      setupRunMocks({ version: v });
      await run();
      expect(mockedCore.setFailed).toHaveBeenCalledWith(
        expect.stringContaining("version")
      );
    });
  });

  it("accepts a valid MAJOR.MINOR.PATCH version", async () => {
    setupRunMocks({ version: "1.2.3" });
    await run();
    expect(mockedCore.setFailed).not.toHaveBeenCalledWith(
      expect.stringContaining("version")
    );
  });
});

// ---------------------------------------------------------------------------
// Group 7: run() -- path traversal validation
// ---------------------------------------------------------------------------

describe("run() - path traversal", () => {
  beforeEach(() => {
    process.env["GITHUB_WORKSPACE"] = FAKE_WORKSPACE;
    process.env["GITHUB_STEP_SUMMARY"] = FAKE_SUMMARY;
  });

  afterEach(() => {
    delete process.env["GITHUB_WORKSPACE"];
    delete process.env["GITHUB_STEP_SUMMARY"];
  });

  it("accepts a safe subdirectory", async () => {
    setupRunMocks({ workingdir: "subdir" });
    await run();
    expect(mockedCore.setFailed).not.toHaveBeenCalledWith(
      expect.stringContaining("resolves outside")
    );
  });

  it("accepts an empty workingdir (resolves to workspace root)", async () => {
    setupRunMocks({ workingdir: "" });
    await run();
    expect(mockedCore.setFailed).not.toHaveBeenCalledWith(
      expect.stringContaining("resolves outside")
    );
  });

  it("rejects a path traversal workingdir", async () => {
    setupRunMocks({ workingdir: "../../etc" });
    await run();
    expect(mockedCore.setFailed).toHaveBeenCalledWith(
      expect.stringContaining("resolves outside")
    );
  });

  it("rejects an absolute path outside the workspace", async () => {
    setupRunMocks({ workingdir: "/etc" });
    await run();
    expect(mockedCore.setFailed).toHaveBeenCalledWith(
      expect.stringContaining("resolves outside")
    );
  });
});

// ---------------------------------------------------------------------------
// Group 8: run() -- empty command validation
// ---------------------------------------------------------------------------

describe("run() - command validation", () => {
  beforeEach(() => {
    process.env["GITHUB_WORKSPACE"] = FAKE_WORKSPACE;
    process.env["GITHUB_STEP_SUMMARY"] = FAKE_SUMMARY;
  });

  afterEach(() => {
    delete process.env["GITHUB_WORKSPACE"];
    delete process.env["GITHUB_STEP_SUMMARY"];
  });

  it("calls setFailed for an empty command", async () => {
    setupRunMocks({ command: "" });
    await run();
    expect(mockedCore.setFailed).toHaveBeenCalledWith(
      expect.stringContaining("command")
    );
  });

  it("calls setFailed for a whitespace-only command", async () => {
    setupRunMocks({ command: "   " });
    await run();
    expect(mockedCore.setFailed).toHaveBeenCalledWith(
      expect.stringContaining("command")
    );
  });

  it("calls setFailed when command cannot be parsed into tokens", async () => {
    // A lone unmatched double-quote passes the trim check but yields null from match()
    setupRunMocks({ command: '"' });
    await run();
    expect(mockedCore.setFailed).toHaveBeenCalledWith(
      expect.stringContaining("could not be parsed")
    );
  });
});

// ---------------------------------------------------------------------------
// Group 9: run() -- exec call shape (array API, no sh -c)
// ---------------------------------------------------------------------------

describe("run() - exec call shape", () => {
  beforeEach(() => {
    process.env["GITHUB_WORKSPACE"] = FAKE_WORKSPACE;
    process.env["GITHUB_STEP_SUMMARY"] = FAKE_SUMMARY;
  });

  afterEach(() => {
    delete process.env["GITHUB_WORKSPACE"];
    delete process.env["GITHUB_STEP_SUMMARY"];
  });

  it("calls exec.exec with witness as the executable", async () => {
    setupRunMocks({ command: "uds run lint" });
    await run();
    expect(mockedExec.exec).toHaveBeenCalledWith(
      "witness",
      expect.any(Array),
      expect.any(Object)
    );
  });

  it("does NOT call exec.exec with sh as the executable", async () => {
    setupRunMocks({ command: "uds run lint" });
    await run();
    const shCalls = mockedExec.exec.mock.calls.filter(([exe]) => exe === "sh");
    expect(shCalls).toHaveLength(0);
  });

  it("passes the command tokens after -- in the args array", async () => {
    setupRunMocks({ command: "echo hello world" });
    await run();
    const [, args] = mockedExec.exec.mock.calls[0];
    const separatorIdx = (args as string[]).indexOf("--");
    expect(separatorIdx).toBeGreaterThan(-1);
    const commandTokens = (args as string[]).slice(separatorIdx + 1);
    expect(commandTokens).toEqual(["echo", "hello", "world"]);
  });

  it("passes cwd in exec options", async () => {
    setupRunMocks({ command: "echo hi", workingdir: "" });
    await run();
    const [, , opts] = mockedExec.exec.mock.calls[0];
    expect((opts as { cwd?: string }).cwd).toBe(FAKE_WORKSPACE);
  });
});

// ---------------------------------------------------------------------------
// Group 10: run() -- multi-GitOID output
// ---------------------------------------------------------------------------

describe("run() - multi-GitOID output", () => {
  beforeEach(() => {
    process.env["GITHUB_WORKSPACE"] = FAKE_WORKSPACE;
    process.env["GITHUB_STEP_SUMMARY"] = FAKE_SUMMARY;
  });

  afterEach(() => {
    delete process.env["GITHUB_WORKSPACE"];
    delete process.env["GITHUB_STEP_SUMMARY"];
  });

  it("emits a single setOutput call with comma-separated OIDs for two GitOIDs", async () => {
    const oid1 = "a".repeat(64);
    const oid2 = "b".repeat(64);
    setupRunMocks({ "enable-archivista": "true" });
    mockedExec.exec.mockImplementation((_cmd, _args, opts) => {
      const listeners = (opts as { listeners?: { stdout?: (d: Buffer) => void } }).listeners;
      listeners?.stdout?.(Buffer.from(`Stored in archivista as ${oid1}\nStored in archivista as ${oid2}`));
      return Promise.resolve(0);
    });
    await run();
    expect(mockedCore.setOutput).toHaveBeenCalledTimes(1);
    expect(mockedCore.setOutput).toHaveBeenCalledWith("git_oid", `${oid1},${oid2}`);
  });

  it("emits empty string when no GitOIDs are found", async () => {
    setupRunMocks();
    mockedExec.exec.mockResolvedValue(0);
    await run();
    expect(mockedCore.setOutput).toHaveBeenCalledWith("git_oid", "");
  });

  it("emits a single OID string (no trailing comma) for one GitOID", async () => {
    const oid = "c".repeat(64);
    setupRunMocks({ "enable-archivista": "true" });
    mockedExec.exec.mockImplementation((_cmd, _args, opts) => {
      const listeners = (opts as { listeners?: { stdout?: (d: Buffer) => void } }).listeners;
      listeners?.stdout?.(Buffer.from(`Stored in archivista as ${oid}`));
      return Promise.resolve(0);
    });
    await run();
    expect(mockedCore.setOutput).toHaveBeenCalledWith("git_oid", oid);
  });
});

// ---------------------------------------------------------------------------
// Group 11: run() -- markdown escaping in job summary
// ---------------------------------------------------------------------------

describe("run() - markdown escaping", () => {
  beforeEach(() => {
    process.env["GITHUB_WORKSPACE"] = FAKE_WORKSPACE;
    process.env["GITHUB_STEP_SUMMARY"] = FAKE_SUMMARY;
  });

  afterEach(() => {
    delete process.env["GITHUB_WORKSPACE"];
    delete process.env["GITHUB_STEP_SUMMARY"];
  });

  it("escapes pipe characters in step name", async () => {
    const oid = "d".repeat(64);
    setupRunMocks({ step: "my|step", "enable-archivista": "true" });
    mockedExec.exec.mockImplementation((_cmd, _args, opts) => {
      const listeners = (opts as { listeners?: { stdout?: (d: Buffer) => void } }).listeners;
      listeners?.stdout?.(Buffer.from(`Stored in archivista as ${oid}`));
      return Promise.resolve(0);
    });
    await run();
    const appendCalls = mockedFs.appendFileSync.mock.calls;
    const tableRowCall = appendCalls.find(([, content]) =>
      typeof content === "string" && content.includes(oid)
    );
    expect(tableRowCall).toBeDefined();
    expect(tableRowCall![1] as string).toContain("my\\|step");
    expect(tableRowCall![1] as string).not.toMatch(/^[^\\]\|step/);
  });

  it("escapes HTML angle brackets in step name", async () => {
    const oid = "e".repeat(64);
    setupRunMocks({ step: "<script>", "enable-archivista": "true" });
    mockedExec.exec.mockImplementation((_cmd, _args, opts) => {
      const listeners = (opts as { listeners?: { stdout?: (d: Buffer) => void } }).listeners;
      listeners?.stdout?.(Buffer.from(`Stored in archivista as ${oid}`));
      return Promise.resolve(0);
    });
    await run();
    const appendCalls = mockedFs.appendFileSync.mock.calls;
    const tableRowCall = appendCalls.find(([, content]) =>
      typeof content === "string" && content.includes(oid)
    );
    expect(tableRowCall).toBeDefined();
    expect(tableRowCall![1] as string).toContain("&lt;script&gt;");
    expect(tableRowCall![1] as string).not.toContain("<script>");
  });

  it("does not write summary header when it already exists in the file", async () => {
    const oid = "f".repeat(64);
    const existingHeader = "## Attestations Created\n| Step | Attestors Run | Attestation GitOID\n| --- | --- | --- |";
    setupRunMocks({ "enable-archivista": "true" });
    mockedFs.readFileSync.mockReturnValue(existingHeader);
    mockedExec.exec.mockImplementation((_cmd, _args, opts) => {
      const listeners = (opts as { listeners?: { stdout?: (d: Buffer) => void } }).listeners;
      listeners?.stdout?.(Buffer.from(`Stored in archivista as ${oid}`));
      return Promise.resolve(0);
    });
    await run();
    const appendCalls = mockedFs.appendFileSync.mock.calls;
    const headerAppends = appendCalls.filter(([, content]) =>
      typeof content === "string" && content.includes("## Attestations Created")
    );
    expect(headerAppends).toHaveLength(0);
  });
});

// ---------------------------------------------------------------------------
// Group 12: run() -- witness download path
// ---------------------------------------------------------------------------

describe("run() - witness download", () => {
  beforeEach(() => {
    process.env["GITHUB_WORKSPACE"] = FAKE_WORKSPACE;
    process.env["GITHUB_STEP_SUMMARY"] = FAKE_SUMMARY;
  });

  afterEach(() => {
    delete process.env["GITHUB_WORKSPACE"];
    delete process.env["GITHUB_STEP_SUMMARY"];
  });

  it("downloads, extracts, and caches witness when not in tool cache", async () => {
    setupRunMocks({ command: "echo hello" });
    mockedTc.find.mockReturnValue("");
    mockedTc.downloadTool.mockResolvedValue("/tmp/witness.tar.gz");
    mockedTc.extractTar.mockResolvedValue("/tmp/witness-extracted");
    mockedTc.cacheFile.mockResolvedValue("/tmp/witness-cached");
    mockedFs.existsSync.mockReturnValue(true);
    await run();
    expect(mockedTc.downloadTool).toHaveBeenCalledWith(
      expect.stringContaining("witness_0.9.2_linux")
    );
    expect(mockedTc.extractTar).toHaveBeenCalledWith("/tmp/witness.tar.gz", expect.any(String));
    expect(mockedTc.cacheFile).toHaveBeenCalled();
    expect(mockedCore.addPath).toHaveBeenCalledWith("/tmp/witness-extracted");
  });

  it("creates install directory when it does not already exist", async () => {
    setupRunMocks({ command: "echo hello" });
    mockedTc.find.mockReturnValue("");
    mockedTc.downloadTool.mockResolvedValue("/tmp/witness.tar.gz");
    mockedTc.extractTar.mockResolvedValue("/tmp/witness-extracted");
    mockedTc.cacheFile.mockResolvedValue("/tmp/witness-cached");
    mockedFs.existsSync.mockReturnValue(false);
    await run();
    expect(mockedFs.mkdirSync).toHaveBeenCalledWith(expect.any(String), { recursive: true });
  });

  it("uses extractZip on win32", async () => {
    const originalPlatform = process.platform;
    Object.defineProperty(process, "platform", { value: "win32", configurable: true });
    setupRunMocks({ command: "echo hello" });
    mockedTc.find.mockReturnValue("");
    mockedTc.downloadTool.mockResolvedValue("/tmp/witness.zip");
    mockedTc.extractZip.mockResolvedValue("/tmp/witness-extracted");
    mockedTc.cacheFile.mockResolvedValue("/tmp/witness-cached");
    mockedFs.existsSync.mockReturnValue(true);
    await run();
    expect(mockedTc.extractZip).toHaveBeenCalledWith("/tmp/witness.zip", expect.any(String));
    expect(mockedTc.extractTar).not.toHaveBeenCalled();
    Object.defineProperty(process, "platform", { value: originalPlatform, configurable: true });
  });
});

// ---------------------------------------------------------------------------
// Group 13: run() -- sigstore defaults
// ---------------------------------------------------------------------------

describe("run() - sigstore defaults", () => {
  beforeEach(() => {
    process.env["GITHUB_WORKSPACE"] = FAKE_WORKSPACE;
    process.env["GITHUB_STEP_SUMMARY"] = FAKE_SUMMARY;
  });

  afterEach(() => {
    delete process.env["GITHUB_WORKSPACE"];
    delete process.env["GITHUB_STEP_SUMMARY"];
  });

  it("applies sigstore endpoint defaults when enable-sigstore is true", async () => {
    setupRunMocks({ "enable-sigstore": "true" });
    await run();
    const [, args] = mockedExec.exec.mock.calls[0];
    expect(args as string[]).toContain("--signer-fulcio-url=https://fulcio.sigstore.dev");
    expect(args as string[]).toContain("--signer-fulcio-oidc-client-id=sigstore");
    expect(args as string[]).toContain(
      "--timestamp-servers=https://timestamp.sigstore.dev/api/v1/timestamp"
    );
  });

  it("does not apply sigstore defaults when enable-sigstore is false", async () => {
    setupRunMocks({ "enable-sigstore": "false" });
    await run();
    const [, args] = mockedExec.exec.mock.calls[0];
    expect(args as string[]).not.toContain("--signer-fulcio-url=https://fulcio.sigstore.dev");
  });
});

// ---------------------------------------------------------------------------
// Group 14: run() -- stderr captured for GitOID extraction
// ---------------------------------------------------------------------------

describe("run() - stderr capture", () => {
  beforeEach(() => {
    process.env["GITHUB_WORKSPACE"] = FAKE_WORKSPACE;
    process.env["GITHUB_STEP_SUMMARY"] = FAKE_SUMMARY;
  });

  afterEach(() => {
    delete process.env["GITHUB_WORKSPACE"];
    delete process.env["GITHUB_STEP_SUMMARY"];
  });

  it("extracts GitOID from stderr output", async () => {
    const oid = "9".repeat(64);
    setupRunMocks({ "enable-archivista": "true" });
    mockedExec.exec.mockImplementation((_cmd, _args, opts) => {
      const listeners = (opts as { listeners?: { stderr?: (d: Buffer) => void } }).listeners;
      listeners?.stderr?.(Buffer.from(`Stored in archivista as ${oid}`));
      return Promise.resolve(0);
    });
    await run();
    expect(mockedCore.setOutput).toHaveBeenCalledWith("git_oid", oid);
  });
});
