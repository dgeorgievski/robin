import fs from 'node:fs';
import { createHash, generateKeyPairSync, randomBytes } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { pathToFileURL } from 'node:url';

async function main(): Promise<void> {
if (process.env.ROB4_COMPARATOR_SCOPE_TEST === '1') {
  runComparatorScopeTest();
  return;
}
const repo = process.env.ROB4_REPO_ROOT!;
const suite = process.env.ROB4_SUITE_DIR!;
const tsRepo = process.env.ROB4_TS_DIR!;
const robinPublicPath = process.env.ROB4_ROBIN_PUBLIC!;
const artifactPath = process.env.ROB4_INTEROP_ARTIFACT!;

for (const [name, value] of Object.entries({ repo, suite, tsRepo, robinPublicPath, artifactPath })) {
  if (!value) throw new Error(`missing ${name}`);
}

const webvh: any = await import(pathToFileURL(`${tsRepo}/dist/esm/index.js`).href);
const cryptoHelpers: any = await import(
  pathToFileURL(`${suite}/implementations/ts/src/cryptography.ts`).href
);
const { Ed25519Signer, PermissiveVerifier, keyFromSeed } = cryptoHelpers;

function ephemeralEd25519(): any {
  return keyFromSeed(randomBytes(32).toString('hex'));
}

function ephemeralX25519(): any {
  const { publicKey } = generateKeyPairSync('x25519');
  const der = publicKey.export({ format: 'der', type: 'spki' }) as Buffer;
  const raw = der.subarray(der.length - 32);
  return {
    type: 'Multikey',
    publicKeyMultibase: webvh.multibaseEncode(
      new Uint8Array([0xec, 0x01, ...raw]),
      webvh.MultibaseEncoding.BASE58_BTC,
    ),
  };
}

function nextKeyHash(publicKeyMultibase: string): string {
  const digest = createHash('sha256').update(publicKeyMultibase).digest();
  return webvh
    .multibaseEncode(new Uint8Array([0x12, 0x20, ...digest]), webvh.MultibaseEncoding.BASE58_BTC)
    .slice(1);
}

function cleanMethod(did: string, fragment: string, vm: any): any {
  return {
    id: `${did}#${fragment}`,
    type: 'Multikey',
    controller: did,
    publicKeyMultibase: vm.publicKeyMultibase,
  };
}

function documentShape(
  did: string,
  authentication: Array<[string, any]>,
  agreements: Array<[string, any]>,
): any {
  return {
    verificationMethods: [
      ...authentication.map(([fragment, vm]) => cleanMethod(did, fragment, vm)),
      ...agreements.map(([fragment, vm]) => cleanMethod(did, fragment, vm)),
    ],
    authentication: authentication.map(([fragment]) => `${did}#${fragment}`),
    keyAgreement: agreements.map(([fragment]) => `${did}#${fragment}`),
  };
}

function rawLog(log: any[]): string {
  return `${log.map((entry) => JSON.stringify(entry)).join('\n')}\n`;
}

function stripPrivate(value: unknown): void {
  const text = JSON.stringify(value);
  for (const forbidden of [
    'secretKeyMultibase',
    'privateKeyJwk',
    'privateKeyMultibase',
    'recoverySecret',
    'seed',
  ]) {
    if (text.includes(forbidden)) throw new Error(`artifact contains ${forbidden}`);
  }
}

function canonical(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(canonical).join(',')}]`;
  if (value && typeof value === 'object') {
    return `{${Object.entries(value as Record<string, unknown>)
      .sort(([a], [b]) => a.localeCompare(b))
      .map(([key, child]) => `${JSON.stringify(key)}:${canonical(child)}`)
      .join(',')}}`;
  }
  return JSON.stringify(value);
}

function normalizeImplicitFilesServiceRoot(snapshot: unknown): unknown {
  const normalized = structuredClone(snapshot);
  if (!normalized || typeof normalized !== 'object') return normalized;
  const didDocument = (normalized as any).didDocument;
  if (!didDocument || typeof didDocument !== 'object' || typeof didDocument.id !== 'string') {
    return normalized;
  }
  const services = didDocument.service;
  if (!Array.isArray(services)) return normalized;
  const filesServiceId = `${didDocument.id}#files`;
  const filesService = services.find(
    (service: unknown) =>
      service && typeof service === 'object' && (service as any).id === filesServiceId,
  );
  if (!filesService || typeof filesService.serviceEndpoint !== 'string') return normalized;
  const endpoint = new URL(filesService.serviceEndpoint);
  if (
    filesService.serviceEndpoint === `${endpoint.origin}/` &&
    endpoint.pathname === '/' &&
    endpoint.search === '' &&
    endpoint.hash === ''
  ) {
    filesService.serviceEndpoint = endpoint.origin;
  }
  return normalized;
}

function serviceEndpoints(snapshot: any): unknown[] {
  const services = snapshot?.didDocument?.service;
  return Array.isArray(services) ? services.map((service) => service.serviceEndpoint) : [];
}

function compare(operation: string, direction: string, robin: any, independent: any): any {
  const byteMatch = JSON.stringify(robin) === JSON.stringify(independent);
  const semanticMatch = canonical(robin) === canonical(independent);
  const normalizedMatch =
    canonical(normalizeImplicitFilesServiceRoot(robin)) ===
    canonical(normalizeImplicitFilesServiceRoot(independent));
  let classification: string | null = null;
  let path: string | null = null;
  if (!byteMatch && semanticMatch) {
    classification = 'EQUIVALENT REPRESENTATION';
    path = '$serialization';
  } else if (!semanticMatch && normalizedMatch) {
    classification = 'SPEC-PERMITTED DIFFERENCE';
    path = '/didDocument/service/*/serviceEndpoint';
  } else if (!normalizedMatch) {
    classification = 'IMPLEMENTATION DEFECT';
    path = '$';
  }
  return {
    operation,
    direction,
    consumed: normalizedMatch,
    byteMatch,
    semanticMatch,
    normalizedSemanticMatch: normalizedMatch,
    classification,
    path,
    robinValue: path
      ? path === '$serialization'
        ? 'JSON member order'
        : path.includes('serviceEndpoint')
          ? serviceEndpoints(robin)
          : robin
      : null,
    independentValue: path
      ? path === '$serialization'
        ? 'JSON member order'
        : path.includes('serviceEndpoint')
          ? serviceEndpoints(independent)
          : independent
      : null,
  };
}

function runComparatorScopeTest(): void {
  const base = {
    didDocument: {
      id: 'did:webvh:test:example.com',
      service: [
        {
          id: 'did:webvh:test:example.com#files',
          type: 'relativeRef',
          serviceEndpoint: 'https://example.com',
        },
        {
          id: 'did:webvh:test:example.com#application',
          type: 'ExampleService',
          serviceEndpoint: 'https://other.example/path',
        },
      ],
    },
    methodParameters: {
      nested: { serviceEndpoint: 'https://nested.example/path' },
    },
  };

  const allowed = structuredClone(base);
  allowed.didDocument.service[0].serviceEndpoint = 'https://example.com/';
  const allowedResult = compare('scope_test', 'self-test', base, allowed);
  if (
    allowedResult.byteMatch !== false ||
    allowedResult.normalizedSemanticMatch !== true ||
    allowedResult.classification !== 'SPEC-PERMITTED DIFFERENCE'
  ) {
    throw new Error('implicit #files root slash was not narrowly normalized');
  }

  const filesPath = structuredClone(base);
  filesPath.didDocument.service[0].serviceEndpoint = 'https://example.com/path/';
  const filesPathBase = structuredClone(base);
  filesPathBase.didDocument.service[0].serviceEndpoint = 'https://example.com/path';
  const filesPathResult = compare('scope_test', 'self-test', filesPathBase, filesPath);
  if (
    filesPathResult.normalizedSemanticMatch !== false ||
    filesPathResult.classification !== 'IMPLEMENTATION DEFECT'
  ) {
    throw new Error('non-root #files endpoint was silently normalized');
  }

  const otherService = structuredClone(base);
  otherService.didDocument.service[1].serviceEndpoint = 'https://other.example/path/';
  const otherServiceResult = compare('scope_test', 'self-test', base, otherService);
  if (
    otherServiceResult.normalizedSemanticMatch !== false ||
    otherServiceResult.classification !== 'IMPLEMENTATION DEFECT'
  ) {
    throw new Error('unrelated DID service endpoint was silently normalized');
  }

  const nested = structuredClone(base);
  nested.methodParameters.nested.serviceEndpoint = 'https://nested.example/path/';
  const nestedResult = compare('scope_test', 'self-test', base, nested);
  if (
    nestedResult.normalizedSemanticMatch !== false ||
    nestedResult.classification !== 'IMPLEMENTATION DEFECT'
  ) {
    throw new Error('same-named field outside didDocument.service was silently normalized');
  }

  console.log('ROB-4 comparator scope test: 4 passed; 0 failed');
}

function tsSnapshot(result: any, log: any[]): any {
  const tip = log[log.length - 1];
  const metadata = result.didDocumentMetadata;
  return {
    didDocument: result.didDocument,
    methodVersion: 'did:webvh:1.0',
    versionId: metadata.versionId,
    versionNumber: Number(metadata.versionId.split('-', 1)[0]),
    versionTime: tip.versionTime,
    methodParameters: tip.parameters,
    deactivated: metadata.deactivated === true,
  };
}

function robinImport(did: string, log: any[], deactivated = false): any {
  const tip = log[log.length - 1];
  const command = spawnSync(
    'cargo',
    ['run', '--quiet', '--locked', '--example', 'import_lifecycle'],
    {
      cwd: repo,
      input: JSON.stringify({
        did,
        rawLog: rawLog(log),
        expectedVersionId: tip.versionId,
        expectedEntryCount: log.length,
        deactivated,
      }),
      encoding: 'utf8',
    },
  );
  if (command.status !== 0) {
    throw new Error(`Robin import failed (${command.status}): ${command.stderr}`);
  }
  return JSON.parse(command.stdout);
}

const comparisons: any[] = [];
const robinPublic = JSON.parse(fs.readFileSync(robinPublicPath, 'utf8'));
const operationOrder = [
  'inception',
  'authentication_add',
  'authentication_rotate',
  'authentication_remove',
  'key_agreement_add',
  'key_agreement_rotate',
  'key_agreement_remove',
  'device_add',
  'device_remove',
  'continuity_replacement',
  'prerotation_disable',
];

for (const operation of operationOrder) {
  const transition = robinPublic.transitions[operation];
  const log = transition.log.trim().split('\n').map(JSON.parse);
  const result = await webvh.resolveDIDFromLog(log);
  if (result.didResolutionMetadata?.error) {
    throw new Error(`independent resolver rejected Robin ${operation}: ${result.didResolutionMetadata.error}`);
  }
  comparisons.push(
    compare(
      operation,
      'Robin -> independent',
      {
        didDocument: transition.document,
        methodVersion: 'did:webvh:1.0',
        versionId: transition.versionId,
        versionNumber: transition.versionNumber,
        versionTime: transition.versionTime,
        methodParameters: transition.parameters,
        deactivated: false,
      },
      tsSnapshot(result, log),
    ),
  );
}

const robinDeactivatedLog = robinPublic.deactivatedLog.trim().split('\n').map(JSON.parse);
const robinDeactivated = await webvh.resolveDIDFromLog(robinDeactivatedLog);
if (robinDeactivated.didDocumentMetadata?.deactivated !== true) {
  throw new Error('independent resolver did not recognize Robin deactivation');
}
comparisons.push({
  operation: 'deactivation',
  direction: 'Robin -> independent',
  consumed: true,
  byteMatch: null,
  semanticMatch: null,
  normalizedSemanticMatch: null,
  classification: 'UNSUPPORTED CAPABILITY',
  path: '/didDocument',
  robinValue: 'not exposed after typed deactivation',
  independentValue: 'document exposed with deactivated=true',
});

const updates = Array.from({ length: 12 }, () => ephemeralEd25519());
const authA = ephemeralEd25519();
const authB = ephemeralEd25519();
const authC = ephemeralEd25519();
const agreementA = ephemeralX25519();
const agreementB = ephemeralX25519();
const agreementC = ephemeralX25519();
const deviceAuth = ephemeralEd25519();
const deviceAgreement = ephemeralX25519();
const signer = (index: number) => new Ed25519Signer({ verificationMethod: updates[index] });

const created = await webvh.createDID({
  address: 'example.com',
  signer: signer(0),
  verifier: signer(0),
  updateKeys: [updates[0].publicKeyMultibase],
  verificationMethods: [authA],
  portable: true,
  nextKeyHashes: [nextKeyHash(updates[1].publicKeyMultibase)],
  created: '2000-01-01T00:00:00Z',
});
const independentDid = created.did;
let independentLog = created.log;

async function recordIndependent(operation: string): Promise<void> {
  stripPrivate(independentLog);
  const independent = await webvh.resolveDIDFromLog(independentLog);
  if (independent.didResolutionMetadata?.error) {
    throw new Error(`independent self-resolution failed for ${operation}`);
  }
  const robin = robinImport(independentDid, independentLog);
  comparisons.push(
    compare(operation, 'independent -> Robin', robin, tsSnapshot(independent, independentLog)),
  );
}

await recordIndependent('inception');

async function update(
  operation: string,
  index: number,
  authentication: Array<[string, any]>,
  agreements: Array<[string, any]>,
): Promise<void> {
  const shape = documentShape(independentDid, authentication, agreements);
  const result = await webvh.updateDID({
    log: independentLog,
    signer: signer(index),
    verifier: new PermissiveVerifier({ verificationMethod: updates[index] }),
    updateKeys: [updates[index].publicKeyMultibase],
    nextKeyHashes: index < 10 ? [nextKeyHash(updates[index + 1].publicKeyMultibase)] : [],
    verificationMethods: shape.verificationMethods,
    authentication: shape.authentication,
    keyAgreement: shape.keyAgreement,
    updated: `2000-01-${String(index + 1).padStart(2, '0')}T00:00:00Z`,
  });
  independentLog = result.log;
  await recordIndependent(operation);
}

await update('authentication_add', 1, [['auth-a1b2c3d4', authA], ['auth-b2c3d4e5', authB]], []);
await update('authentication_rotate', 2, [['auth-b2c3d4e5', authB], ['auth-c3d4e5f6', authC]], []);
await update('authentication_remove', 3, [['auth-c3d4e5f6', authC]], []);
await update('key_agreement_add', 4, [['auth-c3d4e5f6', authC]], [['agreement-a1b2c3d4', agreementA]]);
await update('key_agreement_rotate', 5, [['auth-c3d4e5f6', authC]], [['agreement-b2c3d4e5', agreementB]]);
await update('key_agreement_remove', 6, [['auth-c3d4e5f6', authC]], []);
await update('device_add', 7, [['auth-c3d4e5f6', authC], ['device-a7c9e2f4', deviceAuth]], [['agreement-a7c9e2f4', deviceAgreement]]);
await update('device_remove', 8, [['auth-c3d4e5f6', authC]], []);
await update('continuity_replacement', 9, [['auth-c3d4e5f6', authC]], [['agreement-c3d4e5f6', agreementC]]);
await update('prerotation_disable', 10, [['auth-c3d4e5f6', authC]], [['agreement-c3d4e5f6', agreementC]]);

const deactivated = await webvh.deactivateDID({
  log: independentLog,
  signer: signer(10),
  verifier: signer(10),
});
independentLog = deactivated.log;
stripPrivate(independentLog);
const robinDeactivation = robinImport(independentDid, independentLog, true);
comparisons.push({
  operation: 'deactivation',
  direction: 'independent -> Robin',
  consumed: robinDeactivation.deactivated === true,
  byteMatch: null,
  semanticMatch: null,
  normalizedSemanticMatch: null,
  classification: 'UNSUPPORTED CAPABILITY',
  path: '/didDocument',
  robinValue: 'not exposed after typed deactivation',
  independentValue: 'document exposed with deactivated=true',
});

const defects = comparisons.filter(
  (entry) => !entry.consumed || entry.classification === 'IMPLEMENTATION DEFECT',
);
const artifact = {
  schema: 'robin-rob4-interop-v1',
  pins: {
    specification: 'e426f93e9682bf53952f15b1803f426be5c57fa0',
    didwebvhRs: 'd3cc50049320445ac49eda2b85b8afb5429434be',
    testSuite: 'f792ce4568c8c3efb3b6a055a1c2ba963dc00c35',
    didwebvhTs: '9b899225b304b27adef009083cd9ff3bc98b1f09',
  },
  operations: comparisons.length,
  defects: defects.length,
  comparisons,
  notes: [
    'All signing and relationship key material was generated at runtime and retained only in memory.',
    'Independent versionNumber is derived from the numeric prefix of versionId because the public resolver metadata omits a separate versionNumber field.',
    'X25519 evidence is relationship selection/profile evidence only, not production DH approval.',
  ],
};
stripPrivate(artifact);
fs.writeFileSync(artifactPath, `${JSON.stringify(artifact, null, 2)}\n`);
console.log(`ROB-4 reciprocal comparisons: ${comparisons.length}`);
console.log(`ROB-4 classified differences: ${comparisons.filter((entry) => entry.classification).length}`);
console.log(`ROB-4 implementation defects: ${defects.length}`);
if (defects.length > 0) process.exit(1);
}

main().catch((error: unknown) => {
  console.error(error instanceof Error ? error.message : String(error));
  process.exit(1);
});
