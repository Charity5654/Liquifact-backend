/**
 * Tests for centralized config module.
 *
 * Covers all four issues:
 *  #1302 — Validation boundaries
 *  #1303 — State invariants
 *  #1304 — Failure recovery
 *  #1306 — Compatibility contracts
 */

const mod = require('./index');

const {
  validate,
  validateSafe,
  get,
  getValue,
  getInvoiceFileMaxSize,
  getFeatureFlag,
  logRedactedSummary,
  isValidated,
  _resetForTesting,
  ConfigValidationError,
  ConfigSchema,
  InvoiceFileMaxSizeSchema,
  securityHeaders,
  VALIDATION_BOUNDARIES,
  FEATURE_FLAG_KEYS,
  CONFIG_VERSION,
} = mod;

const VALID_JWT = 'valid-secret-at-least-32-chars-long-here';
const VALID_PROD_ENV = {
  NODE_ENV: 'production',
  JWT_SECRET: VALID_JWT,
  PUBLIC_API_BASE_URL: 'https://api.example.com',
};

// ─────────────────────────────────────────────────────────────────────────────

describe('Config Validation', () => {
  const originalEnv = { ...process.env };

  beforeEach(() => {
    jest.resetModules();
    process.env = { ...originalEnv };
  });

  afterAll(() => {
    process.env = originalEnv;
  });

  // ── Core / defaults ────────────────────────────────────────────────────────

  test('validates minimal config with defaults', () => {
    jest.isolateModules(() => {
      process.env.JWT_SECRET = VALID_JWT;
      const { validate: v } = require('./index');
      const cfg = v();
      expect(cfg.NODE_ENV).toBe('development');
      expect(cfg.PORT).toBe(3001);
      expect(cfg.JWT_SECRET).toBe(VALID_JWT);
      expect(cfg.JWT_ISSUER).toBeUndefined();
      expect(cfg.JWT_AUDIENCE).toBeUndefined();
      expect(cfg.JWT_ALGORITHMS).toBe('HS256');
    });
  });

  test('overrides defaults', () => {
    jest.isolateModules(() => {
      Object.assign(process.env, VALID_PROD_ENV, {
        PORT: '8080',
        JWT_ISSUER: 'custom-issuer',
        JWT_AUDIENCE: 'custom-audience',
        JWT_ALGORITHMS: 'HS256,HS384',
      });
      const { validate: v } = require('./index');
      const cfg = v();
      expect(cfg.PORT).toBe(8080);
      expect(cfg.NODE_ENV).toBe('production');
      expect(cfg.JWT_ISSUER).toBe('custom-issuer');
    });
  });

  // ── #1302: JWT_SECRET boundary ────────────────────────────────────────────

  test('#1302 rejects JWT_SECRET shorter than minimum', () => {
    jest.isolateModules(() => {
      process.env.JWT_SECRET = 'too-short';
      const { validate: v } = require('./index');
      expect(() => v()).toThrow();
    });
  });

  test('#1302 accepts JWT_SECRET exactly at minimum length', () => {
    jest.isolateModules(() => {
      process.env.JWT_SECRET = 'a'.repeat(VALIDATION_BOUNDARIES.SECRET_MIN_LENGTH);
      const { validate: v } = require('./index');
      expect(() => v()).not.toThrow();
    });
  });

  // ── #1302: PORT boundary ──────────────────────────────────────────────────

  test('#1302 rejects PORT below minimum (0)', () => {
    jest.isolateModules(() => {
      process.env.JWT_SECRET = VALID_JWT;
      process.env.PORT = '0';
      const { validate: v } = require('./index');
      expect(() => v()).toThrow();
    });
  });

  test('#1302 rejects PORT above maximum (65536)', () => {
    jest.isolateModules(() => {
      process.env.JWT_SECRET = VALID_JWT;
      process.env.PORT = '65536';
      const { validate: v } = require('./index');
      expect(() => v()).toThrow();
    });
  });

  test('#1302 accepts PORT at boundaries', () => {
    jest.isolateModules(() => {
      process.env.JWT_SECRET = VALID_JWT;
      process.env.PORT = String(VALIDATION_BOUNDARIES.PORT_MIN);
      const { validate: v } = require('./index');
      expect(v().PORT).toBe(VALIDATION_BOUNDARIES.PORT_MIN);
    });
  });

  // ── #1302: Soroban numeric boundaries ────────────────────────────────────

  test('#1302 rejects SOROBAN_BATCH_CONCURRENCY below minimum', () => {
    jest.isolateModules(() => {
      process.env.JWT_SECRET = VALID_JWT;
      process.env.SOROBAN_BATCH_CONCURRENCY = '0';
      const { validate: v } = require('./index');
      expect(() => v()).toThrow();
    });
  });

  test('#1302 rejects SOROBAN_BATCH_CONCURRENCY above maximum', () => {
    jest.isolateModules(() => {
      process.env.JWT_SECRET = VALID_JWT;
      process.env.SOROBAN_BATCH_CONCURRENCY = '51';
      const { validate: v } = require('./index');
      expect(() => v()).toThrow();
    });
  });

  test('#1302 rejects SOROBAN_BATCH_TIMEOUT_MS below minimum', () => {
    jest.isolateModules(() => {
      process.env.JWT_SECRET = VALID_JWT;
      process.env.SOROBAN_BATCH_TIMEOUT_MS = '99';
      const { validate: v } = require('./index');
      expect(() => v()).toThrow();
    });
  });

  // ── #1302: KYC numeric boundaries ────────────────────────────────────────

  test('#1302 rejects KYC_PROVIDER_TIMEOUT_MS below minimum', () => {
    jest.isolateModules(() => {
      process.env.JWT_SECRET = VALID_JWT;
      process.env.KYC_PROVIDER_TIMEOUT_MS = '99';
      const { validate: v } = require('./index');
      expect(() => v()).toThrow();
    });
  });

  test('#1302 rejects KYC_PROVIDER_MAX_RETRIES above maximum', () => {
    jest.isolateModules(() => {
      process.env.JWT_SECRET = VALID_JWT;
      process.env.KYC_PROVIDER_MAX_RETRIES = '11';
      const { validate: v } = require('./index');
      expect(() => v()).toThrow();
    });
  });

  test('#1302 accepts KYC_PROVIDER_MAX_RETRIES at 0 (no retries)', () => {
    jest.isolateModules(() => {
      process.env.JWT_SECRET = VALID_JWT;
      process.env.KYC_PROVIDER_MAX_RETRIES = '0';
      const { validate: v } = require('./index');
      expect(v().KYC_PROVIDER_MAX_RETRIES).toBe(0);
    });
  });

  // ── #1302: Boolean feature-flag strictness ────────────────────────────────

  test('#1302 rejects truthy-but-not-"true" values for feature flags', () => {
    jest.isolateModules(() => {
      process.env.JWT_SECRET = VALID_JWT;
      for (const val of ['1', 'yes', 'TRUE', 'enabled', 'on']) {
        process.env.METRICS_ENABLED = val;
        const { validate: v } = require('./index');
        expect(() => v()).toThrow();
        jest.resetModules();
      }
    });
  });

  // ── #1302: Feature flag defaults ──────────────────────────────────────────

  test('#1302 ESCROW_READ_PROJECTION_ENABLED defaults to "true"', () => {
    jest.isolateModules(() => {
      process.env.JWT_SECRET = VALID_JWT;
      const { validate: v } = require('./index');
      expect(v().ESCROW_READ_PROJECTION_ENABLED).toBe('true');
    });
  });

  test('#1302 ESCROW_INDEXER_ENABLED defaults to "false"', () => {
    jest.isolateModules(() => {
      process.env.JWT_SECRET = VALID_JWT;
      const { validate: v } = require('./index');
      expect(v().ESCROW_INDEXER_ENABLED).toBe('false');
    });
  });

  test('#1302 CONFIG_RUNTIME_ENABLED defaults to "true"', () => {
    jest.isolateModules(() => {
      process.env.JWT_SECRET = VALID_JWT;
      const { validate: v } = require('./index');
      expect(v().CONFIG_RUNTIME_ENABLED).toBe('true');
    });
  });

  test('#1302 INVOICE_STATE_ENABLED defaults to "true"', () => {
    jest.isolateModules(() => {
      process.env.JWT_SECRET = VALID_JWT;
      const { validate: v } = require('./index');
      expect(v().INVOICE_STATE_ENABLED).toBe('true');
    });
  });

  // ── #1302: Cross-field invariants ─────────────────────────────────────────

  test('#1302 rejects half-set KYC (URL without key) in non-test env', () => {
    jest.isolateModules(() => {
      Object.assign(process.env, VALID_PROD_ENV);
      process.env.KYC_PROVIDER_URL = 'https://kyc.example.com';
      delete process.env.KYC_PROVIDER_API_KEY;
      const { validate: v } = require('./index');
      expect(() => v()).toThrow(/KYC_PROVIDER_API_KEY/i);
    });
  });

  test('#1302 rejects half-set KYC (key without URL) in non-test env', () => {
    jest.isolateModules(() => {
      Object.assign(process.env, VALID_PROD_ENV);
      delete process.env.KYC_PROVIDER_URL;
      process.env.KYC_PROVIDER_API_KEY = 'some-key';
      const { validate: v } = require('./index');
      expect(() => v()).toThrow(/KYC_PROVIDER_URL/i);
    });
  });

  test('#1302 allows half-set KYC in test env', () => {
    jest.isolateModules(() => {
      process.env.NODE_ENV = 'test';
      process.env.JWT_SECRET = VALID_JWT;
      process.env.KYC_PROVIDER_URL = 'https://kyc.example.com';
      delete process.env.KYC_PROVIDER_API_KEY;
      const { validate: v } = require('./index');
      expect(() => v()).not.toThrow();
    });
  });

  // ── #1302: PUBLIC_API_BASE_URL production invariants ─────────────────────

  test('#1302 rejects missing PUBLIC_API_BASE_URL in production', () => {
    jest.isolateModules(() => {
      process.env.NODE_ENV = 'production';
      process.env.JWT_SECRET = VALID_JWT;
      delete process.env.PUBLIC_API_BASE_URL;
      const { validate: v } = require('./index');
      expect(() => v()).toThrow(/PUBLIC_API_BASE_URL must be set in production/i);
    });
  });

  test('#1302 rejects non-HTTPS PUBLIC_API_BASE_URL in production', () => {
    jest.isolateModules(() => {
      process.env.NODE_ENV = 'production';
      process.env.JWT_SECRET = VALID_JWT;
      process.env.PUBLIC_API_BASE_URL = 'http://api.example.com';
      const { validate: v } = require('./index');
      expect(() => v()).toThrow(/must use HTTPS/i);
    });
  });

  test('#1302 rejects loopback PUBLIC_API_BASE_URL in production', () => {
    jest.isolateModules(() => {
      process.env.NODE_ENV = 'production';
      process.env.JWT_SECRET = VALID_JWT;
      process.env.PUBLIC_API_BASE_URL = 'https://localhost:3001';
      const { validate: v } = require('./index');
      expect(() => v()).toThrow(/must not be a loopback address/i);
    });
  });

  test('#1302 accepts valid HTTPS non-loopback PUBLIC_API_BASE_URL in production', () => {
    jest.isolateModules(() => {
      Object.assign(process.env, VALID_PROD_ENV, { PUBLIC_API_BASE_URL: 'https://api.liquifact.com' });
      const { validate: v } = require('./index');
      expect(v().PUBLIC_API_BASE_URL).toBe('https://api.liquifact.com');
    });
  });

  // ── #1302: VALIDATION_BOUNDARIES export ──────────────────────────────────

  test('#1302 VALIDATION_BOUNDARIES is exported and frozen', () => {
    expect(VALIDATION_BOUNDARIES).toBeDefined();
    expect(Object.isFrozen(VALIDATION_BOUNDARIES)).toBe(true);
  });

  test('#1302 VALIDATION_BOUNDARIES contains all key limits', () => {
    expect(VALIDATION_BOUNDARIES.SECRET_MIN_LENGTH).toBe(32);
    expect(VALIDATION_BOUNDARIES.PORT_MIN).toBe(1);
    expect(VALIDATION_BOUNDARIES.PORT_MAX).toBe(65535);
    expect(VALIDATION_BOUNDARIES.SOROBAN_BATCH_CONCURRENCY_MIN).toBe(1);
    expect(VALIDATION_BOUNDARIES.SOROBAN_BATCH_CONCURRENCY_MAX).toBe(50);
    expect(VALIDATION_BOUNDARIES.KYC_MAX_RETRIES_MIN).toBe(0);
    expect(VALIDATION_BOUNDARIES.KYC_MAX_RETRIES_MAX).toBe(10);
  });

  // ── #1303: isValidated() ──────────────────────────────────────────────────

  test('#1303 isValidated() returns false before validate()', () => {
    jest.isolateModules(() => {
      const { isValidated: iv } = require('./index');
      expect(iv()).toBe(false);
    });
  });

  test('#1303 isValidated() returns true after successful validate()', () => {
    jest.isolateModules(() => {
      process.env.JWT_SECRET = VALID_JWT;
      const { validate: v, isValidated: iv } = require('./index');
      v();
      expect(iv()).toBe(true);
    });
  });

  test('#1303 isValidated() remains false after failed validate()', () => {
    jest.isolateModules(() => {
      process.env.JWT_SECRET = 'short';
      const { validate: v, isValidated: iv } = require('./index');
      try { v(); } catch (_) {}
      expect(iv()).toBe(false);
    });
  });

  // ── #1303: Singleton immutability ─────────────────────────────────────────

  test('#1303 config object is frozen after validate()', () => {
    jest.isolateModules(() => {
      process.env.JWT_SECRET = VALID_JWT;
      const { validate: v } = require('./index');
      expect(Object.isFrozen(v())).toBe(true);
    });
  });

  test('#1303 mutating a field on returned config has no effect', () => {
    jest.isolateModules(() => {
      process.env.JWT_SECRET = VALID_JWT;
      const { validate: v, get: g } = require('./index');
      const cfg = v();
      const original = cfg.NODE_ENV;
      try { cfg.NODE_ENV = 'hacked'; } catch (_) {}
      expect(g().NODE_ENV).toBe(original);
    });
  });

  // ── #1303: Failed re-validation preserves prior singleton ─────────────────

  test('#1303 failed validate() does not clear a previously-valid singleton', () => {
    jest.isolateModules(() => {
      process.env.JWT_SECRET = VALID_JWT;
      const m = require('./index');
      m.validate();
      const first = m.get();

      process.env.JWT_SECRET = 'short';
      expect(() => m.validate()).toThrow();

      expect(m.isValidated()).toBe(true);
      expect(m.get()).toBe(first);
    });
  });

  // ── #1303: _resetForTesting() ─────────────────────────────────────────────

  test('#1303 _resetForTesting() clears the singleton', () => {
    jest.isolateModules(() => {
      process.env.JWT_SECRET = VALID_JWT;
      const m = require('./index');
      m.validate();
      expect(m.isValidated()).toBe(true);
      m._resetForTesting();
      expect(m.isValidated()).toBe(false);
      expect(() => m.get()).toThrow(/Config not validated/i);
    });
  });

  // ── #1304: ConfigValidationError ─────────────────────────────────────────

  test('#1304 validate() throws ConfigValidationError not raw ZodError', () => {
    jest.isolateModules(() => {
      process.env.JWT_SECRET = 'short';
      const { validate: v, ConfigValidationError: CVE } = require('./index');
      let err;
      try { v(); } catch (e) { err = e; }
      expect(err).toBeInstanceOf(CVE);
      expect(err.code).toBe('CONFIG_VALIDATION_ERROR');
    });
  });

  test('#1304 ConfigValidationError.issues has { path, message } shape', () => {
    jest.isolateModules(() => {
      process.env.JWT_SECRET = 'short';
      const { validate: v } = require('./index');
      let err;
      try { v(); } catch (e) { err = e; }
      expect(Array.isArray(err.issues)).toBe(true);
      err.issues.forEach(i => {
        expect(typeof i.path).toBe('string');
        expect(typeof i.message).toBe('string');
      });
    });
  });

  test('#1304 ConfigValidationError.issues does not contain secret values', () => {
    jest.isolateModules(() => {
      const secret = 'my-real-secret-do-not-leak-ever';
      process.env.JWT_SECRET = secret;
      const { validate: v } = require('./index');
      let err;
      try { v(); } catch (e) { err = e; }
      expect(JSON.stringify(err.issues)).not.toContain(secret);
    });
  });

  // ── #1304: validateSafe() ─────────────────────────────────────────────────

  test('#1304 validateSafe() returns { ok: true, config } on valid env', () => {
    jest.isolateModules(() => {
      process.env.JWT_SECRET = VALID_JWT;
      const { validateSafe: vs } = require('./index');
      const r = vs();
      expect(r.ok).toBe(true);
      expect(r.config).toBeDefined();
      expect(r.error).toBeUndefined();
    });
  });

  test('#1304 validateSafe() returns { ok: false, error } on invalid env', () => {
    jest.isolateModules(() => {
      process.env.JWT_SECRET = 'short';
      const { validateSafe: vs } = require('./index');
      const r = vs();
      expect(r.ok).toBe(false);
      expect(r.error).toBeDefined();
      expect(r.config).toBeUndefined();
    });
  });

  test('#1304 validateSafe() never throws — even with empty env', () => {
    jest.isolateModules(() => {
      process.env = {};
      const { validateSafe: vs } = require('./index');
      expect(() => vs()).not.toThrow();
      expect(vs().ok).toBe(false);
    });
  });

  test('#1304 validateSafe() recovers after env is fixed', () => {
    jest.isolateModules(() => {
      process.env.JWT_SECRET = 'short';
      const m = require('./index');
      expect(m.validateSafe().ok).toBe(false);

      process.env.JWT_SECRET = VALID_JWT;
      const r = m.validateSafe();
      expect(r.ok).toBe(true);
      expect(r.config.JWT_SECRET).toBe(VALID_JWT);
    });
  });

  // ── #1304: logRedactedSummary edge cases ──────────────────────────────────

  test('#1304 logRedactedSummary handles ConfigValidationError without leaking secrets', () => {
    jest.isolateModules(() => {
      const consoleSpy = jest.spyOn(console, 'error').mockImplementation(() => {});
      const secret = 'ultra-secret-value-99999';
      process.env.JWT_SECRET = secret;
      const { validate: v, logRedactedSummary: lrs } = require('./index');
      let err;
      try { v(); } catch (e) { err = e; }
      lrs(err);
      const out = consoleSpy.mock.calls.flat().join('\n');
      expect(out).toContain('JWT_SECRET');
      expect(out).not.toContain(secret);
      consoleSpy.mockRestore();
    });
  });

  test('#1304 logRedactedSummary handles null/undefined without throwing', () => {
    const spy = jest.spyOn(console, 'error').mockImplementation(() => {});
    expect(() => logRedactedSummary(null)).not.toThrow();
    expect(() => logRedactedSummary(undefined)).not.toThrow();
    spy.mockRestore();
  });

  // ── #1304: getInvoiceFileMaxSize safe fallback ────────────────────────────

  test('#1304 getInvoiceFileMaxSize returns "5mb" when env missing and singleton absent', () => {
    jest.isolateModules(() => {
      delete process.env.INVOICE_FILE_MAX_SIZE;
      const { getInvoiceFileMaxSize: gifs } = require('./index');
      expect(gifs()).toBe('5mb');
    });
  });

  test('#1304 getInvoiceFileMaxSize returns "5mb" when env value is invalid', () => {
    jest.isolateModules(() => {
      process.env.INVOICE_FILE_MAX_SIZE = 'not-a-size';
      const { getInvoiceFileMaxSize: gifs } = require('./index');
      expect(gifs()).toBe('5mb');
    });
  });

  // ── #1306: Export surface ─────────────────────────────────────────────────

  test('#1306 all original exports are present with correct types', () => {
    expect(typeof mod.validate).toBe('function');
    expect(typeof mod.get).toBe('function');
    expect(typeof mod.getValue).toBe('function');
    expect(typeof mod.getInvoiceFileMaxSize).toBe('function');
    expect(typeof mod.logRedactedSummary).toBe('function');
    expect(typeof mod.ConfigSchema.parse).toBe('function');
    expect(typeof mod.InvoiceFileMaxSizeSchema.parse).toBe('function');
    expect(typeof mod.securityHeaders).toBe('object');
  });

  test('#1306 CONFIG_VERSION is a semver string', () => {
    expect(typeof CONFIG_VERSION).toBe('string');
    expect(CONFIG_VERSION).toMatch(/^\d+\.\d+\.\d+$/);
  });

  test('#1306 FEATURE_FLAG_KEYS is a frozen array with expected keys', () => {
    expect(Array.isArray(FEATURE_FLAG_KEYS)).toBe(true);
    expect(Object.isFrozen(FEATURE_FLAG_KEYS)).toBe(true);
    for (const key of ['ESCROW_INDEXER_ENABLED', 'ESCROW_READ_PROJECTION_ENABLED',
      'INVOICE_STATE_ENABLED', 'CONFIG_RUNTIME_ENABLED', 'METRICS_ENABLED']) {
      expect(FEATURE_FLAG_KEYS).toContain(key);
    }
  });

  // ── #1306: getFeatureFlag() ───────────────────────────────────────────────

  test('#1306 getFeatureFlag returns boolean for all flag keys', () => {
    jest.isolateModules(() => {
      process.env.JWT_SECRET = VALID_JWT;
      const { validate: v, getFeatureFlag: gff, FEATURE_FLAG_KEYS: fk } = require('./index');
      v();
      fk.forEach(key => {
        expect(typeof gff(key)).toBe('boolean');
      });
    });
  });

  test('#1306 getFeatureFlag returns true for flags defaulting to "true"', () => {
    jest.isolateModules(() => {
      process.env.JWT_SECRET = VALID_JWT;
      const { validate: v, getFeatureFlag: gff } = require('./index');
      v();
      expect(gff('ESCROW_READ_PROJECTION_ENABLED')).toBe(true);
      expect(gff('INVOICE_STATE_ENABLED')).toBe(true);
      expect(gff('CONFIG_RUNTIME_ENABLED')).toBe(true);
      expect(gff('METRICS_ENABLED')).toBe(true);
    });
  });

  test('#1306 getFeatureFlag returns false for flags defaulting to "false"', () => {
    jest.isolateModules(() => {
      process.env.JWT_SECRET = VALID_JWT;
      const { validate: v, getFeatureFlag: gff } = require('./index');
      v();
      expect(gff('ESCROW_INDEXER_ENABLED')).toBe(false);
      expect(gff('KYC_WEBHOOK_ENABLED')).toBe(false);
      expect(gff('CURSOR_TTL_ENABLED')).toBe(false);
    });
  });

  test('#1306 getFeatureFlag throws TypeError for unknown key', () => {
    jest.isolateModules(() => {
      process.env.JWT_SECRET = VALID_JWT;
      const { validate: v, getFeatureFlag: gff } = require('./index');
      v();
      expect(() => gff('NOT_A_FLAG')).toThrow(TypeError);
      expect(() => gff('NOT_A_FLAG')).toThrow(/NOT_A_FLAG/);
    });
  });

  test('#1306 getFeatureFlag throws before validate()', () => {
    jest.isolateModules(() => {
      const { getFeatureFlag: gff } = require('./index');
      expect(() => gff('METRICS_ENABLED')).toThrow(/Config not validated/i);
    });
  });

  test('#1306 getValue() and getFeatureFlag() agree on flag values', () => {
    jest.isolateModules(() => {
      process.env.JWT_SECRET = VALID_JWT;
      process.env.METRICS_ENABLED = 'false';
      const { validate: v, getValue: gv, getFeatureFlag: gff } = require('./index');
      v();
      expect(gv('METRICS_ENABLED') === 'true').toBe(gff('METRICS_ENABLED'));
    });
  });

  // ── #1306: securityHeaders contract ──────────────────────────────────────

  test('#1306 securityHeaders.hsts has correct values', () => {
    expect(securityHeaders.hsts.maxAge).toBe(31536000);
    expect(securityHeaders.hsts.includeSubDomains).toBe(true);
    expect(securityHeaders.hsts.preload).toBe(true);
  });

  test('#1306 securityHeaders.docsContentSecurityPolicy allows unsafe-inline', () => {
    expect(securityHeaders.docsContentSecurityPolicy.directives.scriptSrc)
      .toContain("'unsafe-inline'");
  });

  // ── #1306: InvoiceFileMaxSizeSchema contract ───────────────────────────────

  test('#1306 InvoiceFileMaxSizeSchema defaults to "5mb"', () => {
    expect(InvoiceFileMaxSizeSchema.parse(undefined)).toBe('5mb');
  });

  test('#1306 InvoiceFileMaxSizeSchema accepts valid size strings', () => {
    expect(InvoiceFileMaxSizeSchema.parse('512kb')).toBe('512kb');
    expect(InvoiceFileMaxSizeSchema.parse('1mb')).toBe('1mb');
  });

  test('#1306 InvoiceFileMaxSizeSchema rejects invalid strings', () => {
    expect(() => InvoiceFileMaxSizeSchema.parse('not-a-size')).toThrow();
  });

  // ── Schema direct usage ───────────────────────────────────────────────────

  test('schema direct parse', () => {
    const result = ConfigSchema.parse({
      NODE_ENV: 'test',
      PORT: 3001,
      JWT_SECRET: '0123456789abcdef0123456789abcdef',
    });
    expect(result).toMatchObject({ NODE_ENV: 'test', PORT: 3001 });
  });
});
