/**
 * @fileoverview Verificador FCrDNS (Forward-Confirmed Reverse DNS) para crawlers legítimos (N-02).
 * Nunca confía en un User-Agent "Googlebot" o "Bingbot" sin verificación DNS inversa + directa.
 * Política fail-closed: mientras la IP no esté verificada por DNS, se trata como visitante normal.
 */

import dns from 'node:dns/promises';
import net from 'node:net';

const BOT_RULES = [
  {
    name: 'Googlebot',
    uaRegex: /\b(?:googlebot|adsbot-google|mediapartners-google|google-inspectiontool)\b/i,
    allowedSuffixes: ['.googlebot.com', '.google.com', '.googleusercontent.com']
  },
  {
    name: 'Bingbot',
    uaRegex: /\b(?:bingbot|adidxbot|bingpreview)\b/i,
    allowedSuffixes: ['.search.msn.com']
  },
  {
    name: 'Applebot',
    uaRegex: /\bapplebot\b/i,
    allowedSuffixes: ['.applebot.apple.com']
  },
  {
    name: 'DuckDuckBot',
    uaRegex: /\bduckduckbot\b/i,
    allowedSuffixes: ['.duckduckgo.com']
  }
];

const VERIFIED_TTL_MS = 60 * 60 * 1000;   // 1 hora
const UNVERIFIED_TTL_MS = 15 * 60 * 1000; // 15 minutos
const MAX_CACHE_ENTRIES = 2000;

export function matchClaimedSearchBot(userAgent = '') {
  const ua = String(userAgent || '');
  if (!ua) return null;
  for (const rule of BOT_RULES) {
    if (rule.uaRegex.test(ua)) return rule;
  }
  return null;
}

export class SearchBotVerifier {
  /**
   * @param {object} [options]
   * @param {object} [options.dnsResolver] Resolver inyectable `{ reverse(ip), lookup(host, opts) }` para tests offline
   * @param {boolean} [options.enableLiveDns=true]
   */
  constructor({ dnsResolver = null, enableLiveDns = true } = {}) {
    this.dnsResolver = dnsResolver || dns;
    this.enableLiveDns = enableLiveDns;
    this.cache = new Map(); // `${rule.name}:${ip}` -> { verified: boolean, expiresAt: number }
    this.inFlight = new Set();
  }

  _normalizeIp(ip) {
    return String(ip || '').replace(/^::ffff:/, '').trim().toLowerCase();
  }

  _pruneCacheIfNeeded() {
    if (this.cache.size <= MAX_CACHE_ENTRIES) return;
    const oldest = this.cache.keys().next().value;
    if (oldest) this.cache.delete(oldest);
  }

  /**
   * Consulta síncrona (fail-closed) usada en la ruta caliente de inspección HTTP.
   * Si la IP no está en caché verificada, dispara verificación FCrDNS en segundo plano y devuelve `false`.
   */
  isVerifiedSearchBot(ip, userAgent = '') {
    const rule = matchClaimedSearchBot(userAgent);
    if (!rule) return false;

    const cleanIp = this._normalizeIp(ip);
    if (!cleanIp || net.isIP(cleanIp) === 0) return false;

    // Loopback / privadas jamás son crawlers públicos oficiales de Google/Bing
    if (
      cleanIp === '127.0.0.1' ||
      cleanIp === '::1' ||
      cleanIp.startsWith('10.') ||
      cleanIp.startsWith('192.168.') ||
      cleanIp.startsWith('169.254.')
    ) {
      return false;
    }

    const cacheKey = `${rule.name}:${cleanIp}`;
    const cached = this.cache.get(cacheKey);
    if (cached && Date.now() < cached.expiresAt) {
      return cached.verified;
    }

    if (this.enableLiveDns && !this.inFlight.has(cacheKey)) {
      this.verifyAsync(cleanIp, userAgent).catch(() => {});
    }
    return false;
  }

  /**
   * Ejecuta la verificación FCrDNS completa (PTR -> sufijo oficial -> A/AAAA coincide con IP).
   */
  async verifyAsync(ip, userAgent = '') {
    const rule = matchClaimedSearchBot(userAgent);
    if (!rule) return false;

    const cleanIp = this._normalizeIp(ip);
    if (!cleanIp || net.isIP(cleanIp) === 0) return false;

    const cacheKey = `${rule.name}:${cleanIp}`;
    const existing = this.cache.get(cacheKey);
    if (existing && Date.now() < existing.expiresAt) {
      return existing.verified;
    }

    this.inFlight.add(cacheKey);
    let verified = false;
    try {
      const hostnames = await Promise.race([
        this.dnsResolver.reverse(cleanIp),
        new Promise((_, reject) => setTimeout(() => reject(new Error('DNS timeout')), 2500))
      ]);

      if (Array.isArray(hostnames)) {
        for (const rawHost of hostnames) {
          const host = String(rawHost || '').toLowerCase().replace(/\.$/, '');
          const suffixOk = rule.allowedSuffixes.some((sfx) => host.endsWith(sfx));
          if (!suffixOk) continue;

          const resolved = await Promise.race([
            this.dnsResolver.lookup(host, { all: true }),
            new Promise((_, reject) => setTimeout(() => reject(new Error('DNS timeout')), 2500))
          ]);

          const addresses = Array.isArray(resolved)
            ? resolved.map((r) => this._normalizeIp(r.address || r))
            : [];
          if (addresses.includes(cleanIp)) {
            verified = true;
            break;
          }
        }
      }
    } catch {
      verified = false;
    } finally {
      this.inFlight.delete(cacheKey);
      this._pruneCacheIfNeeded();
      this.cache.set(cacheKey, {
        verified,
        expiresAt: Date.now() + (verified ? VERIFIED_TTL_MS : UNVERIFIED_TTL_MS)
      });
    }

    return verified;
  }

  clearCache() {
    this.cache.clear();
  }
}
