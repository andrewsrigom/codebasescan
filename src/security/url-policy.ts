import { isIP } from 'node:net';
import { lookup } from 'node:dns/promises';

export interface ResolvedAddress {
  address: string;
  family: number;
}

export interface ValidatedProbeTarget {
  url: URL;
  displayUrl: string;
  addresses: ResolvedAddress[];
}

export type AddressResolver = (hostname: string) => Promise<ResolvedAddress[]>;

const metadataHosts = new Set([
  '169.254.169.254',
  'fd00:ec2::254',
  'metadata.google.internal',
  'metadata.goog',
  'instance-data.ec2.internal',
]);

function parseIpv4(value: string): number[] | null {
  const parts = value.split('.');
  if (parts.length !== 4) return null;
  const numbers = parts.map(Number);
  return numbers.every((part) => Number.isInteger(part) && part >= 0 && part <= 255)
    ? numbers
    : null;
}

function ipv4Class(value: string): 'loopback' | 'private' | 'forbidden' | 'public' {
  const parts = parseIpv4(value);
  if (!parts) return 'forbidden';
  const [a = 0, b = 0, c = 0] = parts;
  if (a === 127) return 'loopback';
  if (
    a === 0 ||
    (a === 169 && b === 254) ||
    a >= 224 ||
    (a === 192 && b === 0 && c === 0) ||
    (a === 192 && b === 0 && c === 2) ||
    (a === 198 && b === 51 && c === 100) ||
    (a === 203 && b === 0 && c === 113)
  )
    return 'forbidden';
  if (
    a === 10 ||
    (a === 100 && b >= 64 && b <= 127) ||
    (a === 172 && b >= 16 && b <= 31) ||
    (a === 192 && b === 168) ||
    (a === 198 && (b === 18 || b === 19))
  )
    return 'private';
  return 'public';
}

function ipv6Class(value: string): 'loopback' | 'private' | 'forbidden' | 'public' {
  const normalized = value.toLowerCase().split('%')[0] ?? '';
  if (normalized === '::1') return 'loopback';
  if (normalized === '::') return 'forbidden';
  const mapped = /^::ffff:(\d+\.\d+\.\d+\.\d+)$/.exec(normalized);
  if (mapped?.[1]) return ipv4Class(mapped[1]);
  if (/^(?:fc|fd)/.test(normalized)) return 'private';
  if (/^fe[89ab]/.test(normalized) || /^ff/.test(normalized) || /^2001:db8/.test(normalized))
    return 'forbidden';
  return 'public';
}

function addressClass(value: string): 'loopback' | 'private' | 'forbidden' | 'public' {
  const family = isIP(value);
  return family === 4 ? ipv4Class(value) : family === 6 ? ipv6Class(value) : 'forbidden';
}

function isLocalhost(hostname: string): boolean {
  const normalized = hostname.toLowerCase().replace(/\.$/, '');
  return normalized === 'localhost' || normalized.endsWith('.localhost');
}

export const systemResolver: AddressResolver = async (hostname) =>
  lookup(hostname, { all: true, verbatim: true });

export async function validateProbeUrl(
  raw: string,
  allowPrivateNetwork: boolean,
  resolver: AddressResolver = systemResolver,
): Promise<ValidatedProbeTarget> {
  let url: URL;
  try {
    url = new URL(raw);
  } catch {
    throw new Error('HTTP probe target must be an absolute URL.');
  }
  if (!['http:', 'https:'].includes(url.protocol))
    throw new Error('HTTP probe target must use http or https.');
  if (url.username || url.password)
    throw new Error('HTTP probe target cannot contain credentials.');
  if (url.hash) throw new Error('HTTP probe target cannot contain a fragment.');
  if (
    [...url.searchParams.keys()].some((key) => /token|secret|password|api[-_]?key|auth/i.test(key))
  )
    throw new Error('HTTP probe target cannot contain credential-shaped query parameters.');
  const hostname = url.hostname
    .toLowerCase()
    .replace(/^\[|\]$/g, '')
    .replace(/\.$/, '');
  if (!hostname || metadataHosts.has(hostname) || hostname.endsWith('.internal'))
    throw new Error('Cloud metadata and internal service targets are blocked.');
  const port = url.port ? Number(url.port) : url.protocol === 'https:' ? 443 : 80;
  if (!Number.isInteger(port) || port < 1 || port > 65535)
    throw new Error('HTTP probe target has an invalid port.');
  let addresses: ResolvedAddress[];
  if (isIP(hostname)) addresses = [{ address: hostname, family: isIP(hostname) }];
  else {
    try {
      addresses = await resolver(hostname);
    } catch {
      throw new Error('HTTP probe target could not be resolved.');
    }
  }
  if (!addresses.length) throw new Error('HTTP probe target did not resolve to an address.');
  const localhost =
    isLocalhost(hostname) || addresses.every((item) => addressClass(item.address) === 'loopback');
  for (const item of addresses) {
    if (item.family !== 4 && item.family !== 6)
      throw new Error('HTTP probe target resolved to an unsupported address family.');
    const classification = addressClass(item.address);
    if (classification === 'forbidden')
      throw new Error(
        'HTTP probe target resolved to a forbidden, reserved, or link-local address.',
      );
    if (classification === 'loopback' && !localhost)
      throw new Error('A non-localhost target cannot resolve to loopback.');
    if (classification === 'private' && !allowPrivateNetwork)
      throw new Error('Private-network targets require explicit allowPrivateNetwork approval.');
  }
  const display = new URL(url);
  display.search = '';
  return {
    url,
    displayUrl: display.toString(),
    addresses,
  };
}
