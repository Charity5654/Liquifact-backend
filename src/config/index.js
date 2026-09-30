/**
 * Centralized typed configuration module with runtime validation.
 * Uses Zod for schema validation and type safety.
 *
 * ## Public API contract  (#1306)
 *
 * The following exports form the public contract of this module. Any breaking
 * change must include a migration path documented here and tested in the
 * companion test suite.
 *
 * ### Functions
 * | Export                    | Signature                                    | Since   |
 * |---------------------------|----------------------------------------------|---------|
 * | `validate()`              | `() => Config`                               | initial |
 * | `validateSafe()`          | `() => { ok, config } | { ok, error }`       | #1304   |
 * | `get()`                   | `() => Config`                               | initial |
 * | `getValue(key)`           | `(key: keyof Config) => Config[key]`         | initial |
 * | `getInvoiceFileMaxSize()` | `() => string`                               | initial |
 * | `getFeatureFlag(key)`     | `(key: FeatureFlagKey) => boolean`           | #1306   |
 * | `logRedactedSummary(err)` | `(err) => void`                              | initial |
 * | `isValidated()`           | `() => boolean`                              | #1303   |
 * | `_resetForTesting()`      | `() => void`  — TEST USE ONLY                | #1303   |
 *
 * ### Classes / schemas
 * | Export                    | Type            | Since   |
 * |---------------------------|-----------------|---------|
 * | `ConfigValidationError`   | Error subclass  | #1304   |
 * | `ConfigSchema`            | ZodObject       | initial |
 * | `InvoiceFileMaxSizeSchema`| ZodString       | initial |
 *
 * ### Objects / constants
 * | Export               | Type              | Since   |
 * |----------------------|-------------------|---------|
 * | `securityHeaders`    | plain object      | initial |
 * | `VALIDATION_BOUNDARIES` | frozen object  | #1302   |
 * | `FEATURE_FLAG_KEYS`  | frozen array      | #1306   |
 * | `CONFIG_VERSION`     | string (semver)   | #1306   |
 *
 * ### Compatibility guarantees
 * 1. All "initial" exports are preserved with identical signatures.
 * 2. `getFeatureFlag()` is additive — `getValue()` for flags still works.
 * 3. `validateSafe()` is additive — `validate()` still throws on failure.
 * 4. `CONFIG_VERSION` minor bump signals new additive exports; major bump
 *    signals a breaking change and requires a migration guide.
 *
 * ## Validation boundaries  (#1302)
 *
 * Every environment variable has an explicit boundary:
 *   - Numeric knobs have min/max guards with descriptive messages.
 *   - Secrets have minimum-length guards; no default is provided.
 *   - Boolean flags accept only "true" | "false" — no truthy aliases.
 *   - Cross-field invariants are enforced in a single `superRefine` pass.
 *   - `VALIDATION_BOUNDARIES` exports all limits as a frozen object.
 *
 * ## State invariants  (#1303)
 *
 * 1. The singleton is deeply frozen after `validate()` succeeds.
 * 2. A failed `validate()` / `validateSafe()` never overwrites a prior
 *    valid singleton.
 * 3. `isValidated()` lets callers check readiness without triggering the
 *    guard error thrown by `get()`.
 * 4. `_resetForTesting()` clears the singleton for test isolation only.
 *
 * ## Failure recovery  (#1304)
 *
 * 1. `validate()` always throws `ConfigValidationError` — never a raw ZodError.
 * 2. `validateSafe()` never throws; returns a discriminated-union result.
 * 3. `ConfigValidationError` exposes `.code`, `.issues`, `.cause` — no secrets.
 * 4. `getInvoiceFileMaxSize()` falls back to "5mb" when env is missing/invalid.
 *
 * @module config
 */

const z = require('zod');

// ─── Public API version  (#1306) ──────────────────────────────────────────────

/**
 * Semantic version of the config module's public API.
 * Bump minor for additive exports; bump major for breaking changes.
 * @type {string}
 */
const CONFIG_VERSION = '1.1.0';

// ─── Validation boundary constants  (#1302) ───────────────────────────────────

const SECRET_MIN_LENGTH = 32;
const PORT_MIN = 1;
const PORT_MAX = 65535;
const SOROBAN_BATCH_CONCURRENCY_MIN = 1;
const SOROBAN_BATCH_CONCURRENCY_MAX = 50;
const SOROBAN_BATCH_TIMEOUT_MS_MIN = 100;
const SOROBAN_BATCH_TIMEOUT_MS_MAX = 30_000;
const KYC_TIMEOUT_MS_MIN = 100;
const KYC_TIMEOUT_MS_MAX = 30_000;
const KYC_MAX_RETRIES_MIN = 0;
const KYC_MAX_RETRIES_MAX = 10;
const KYC_BASE_DELAY_MS_MIN = 0;
const KYC_BASE_DELAY_MS_MAX = 10_000;
const KYC_MAX_DELAY_MS_MIN = 0;
const KYC_MAX_DELAY_MS_MAX = 60_000;
const KYC_CB_FAILURE_THRESHOLD_MIN = 1;
const KYC_CB_FAILURE_THRESHOLD_MAX = 100;
const KYC_CB_RECOVERY_TIMEOUT_MS_MIN = 100;
const KYC_CB_RECOVERY_TIMEOUT_MS_MAX = 60_000;
const CURSOR_TTL_SECONDS_MIN = 1;
const ESCROW_INDEXER_STALE_THRESHOLD_SECONDS_MIN = 1;

/**
 * Exported boundary constants so callers can reference the same limits that
 * the schema enforces without duplicating magic numbers.
 */
const VALIDATION_BOUNDARIES = Object.freeze({
  SECRET_MIN_LENGTH,
  PORT_MIN,
  PORT_MAX,
  SOROBAN_BATCH_CONCURRENCY_MIN,
  SOROBAN_BATCH_CONCURRENCY_MAX,
  SOROBAN_BATCH_TIMEOUT_MS_MIN,
  SOROBAN_BATCH_TIMEOUT_MS_MAX,
  KYC_TIMEOUT_MS_MIN,
  KYC_TIMEOUT_MS_MAX,
  KYC_MAX_RETRIES_MIN,
  KYC_MAX_RETRIES_MAX,
  KYC_BASE_DELAY_MS_MIN,
  KYC_BASE_DELAY_MS_MAX,
  KYC_MAX_DELAY_MS_MIN,
  KYC_MAX_DELAY_MS_MAX,
  KYC_CB_FAILURE_THRESHOLD_MIN,
  KYC_CB_FAILURE_THRESHOLD_MAX,
  KYC_CB_RECOVERY_TIMEOUT_MS_MIN,
  KYC_CB_RECOVERY_TIMEOUT_MS_MAX,
  CURSOR_TTL_SECONDS_MIN,
  ESCROW_INDEXER_STALE_THRESHOLD_SECONDS_MIN,
});

// ─── Feature-flag key registry  (#1306) ───────────────────────────────────────

/**
 * Canonical list of all boolean feature-flag keys in the config schema.
 * Source of truth for `getFeatureFlag()` key validation.
 * @type {readonly string[]}
 */
const FEATURE_FLAG_KEYS = Object.freeze([
  'ESCROW_INDEXER_ENABLED',
  'ESCROW_READ_PROJECTION_ENABLED',
  'INVOICE_STATE_ENABLED',
  'CONFIG_RUNTIME_ENABLED',
  'KYC_WEBHOOK_ENABLED',
  'KYC_PROVIDER_SIGN_REQUESTS',
  'KYC_PROVIDER_VERIFY_RESPONSE_SIGNATURE',
  'CURSOR_TTL_ENABLED',
  'METRICS_ENABLED',
]);

// ─── Sub-schemas ───────────────────────────────────────────────────────────────

/**
 * Express-compatible request size string accepted by body-parser.
 * Examples: "512kb", "5mb", "1.5gb".
 * @type {z.ZodDefault<z.ZodString>}
 */
const InvoiceFileMaxSizeSchema = z
  .string()
  .trim()
  .regex(/^\d+(?:\.\d+)?(?:b|kb|mb|gb)$/i, {
    message: 'INVOICE_FILE_MAX_SIZE must be a size such as 512kb or 5mb.',
  })
  .default('5mb');

// ─── Main schema  (#1302) ────────────────────────────────────────────────────

/**
 * Complete configuration schema with explicit boundaries on every field.
 * @type {z.ZodObject<any>}
 */
const ConfigSchema = z
  .object({
    NODE_ENV: z.enum(['development', 'production', 'test']).default('development'),

    PORT: z.coerce
      .number()
      .int({ message: 'PORT must be an integer.' })
      .min(PORT_MIN, { message: `PORT must be at least ${PORT_MIN}.` })
      .max(PORT_MAX, { message: `PORT must be at most ${PORT_MAX}.` })
      .default(3001),

    /** No default — must be explicitly set. */
    JWT_SECRET: z.string().min(SECRET_MIN_LENGTH, {
      message: `JWT_SECRET must be at least ${SECRET_MIN_LENGTH} characters.`,
    }),

    JWT_ALGORITHMS: z.string().optional().default('HS256'),
    JWT_ISSUER: z.string().optional(),
    JWT_AUDIENCE: z.string().optional(),

    CURSOR_SECRET: z.string().min(SECRET_MIN_LENGTH, {
      message: `CURSOR_SECRET must be at least ${SECRET_MIN_LENGTH} characters.`,
    }).optional(),

    CURSOR_TTL_ENABLED: z.enum(['true', 'false']).default('false'),

    CURSOR_TTL_SECONDS: z.coerce
      .number()
      .int()
      .min(CURSOR_TTL_SECONDS_MIN, {
        message: `CURSOR_TTL_SECONDS must be at least ${CURSOR_TTL_SECONDS_MIN}.`,
      })
      .default(3600),

    CORS_ALLOWED_ORIGINS: z.string().optional(),

    SOROBAN_RPC_URL: z.string().url().default('https://soroban-testnet.stellar.org'),
    NETWORK_PASSPHRASE: z.string().default('Test SDF Network ; September 2015'),

    SOROBAN_BATCH_CONCURRENCY: z.coerce
      .number()
      .int()
      .min(SOROBAN_BATCH_CONCURRENCY_MIN, {
        message: `SOROBAN_BATCH_CONCURRENCY must be at least ${SOROBAN_BATCH_CONCURRENCY_MIN}.`,
      })
      .max(SOROBAN_BATCH_CONCURRENCY_MAX, {
        message: `SOROBAN_BATCH_CONCURRENCY must be at most ${SOROBAN_BATCH_CONCURRENCY_MAX}.`,
      })
      .default(5),

    SOROBAN_BATCH_TIMEOUT_MS: z.coerce
      .number()
      .int()
      .min(SOROBAN_BATCH_TIMEOUT_MS_MIN, {
        message: `SOROBAN_BATCH_TIMEOUT_MS must be at least ${SOROBAN_BATCH_TIMEOUT_MS_MIN} ms.`,
      })
      .max(SOROBAN_BATCH_TIMEOUT_MS_MAX, {
        message: `SOROBAN_BATCH_TIMEOUT_MS must be at most ${SOROBAN_BATCH_TIMEOUT_MS_MAX} ms.`,
      })
      .default(5000),

    ESCROW_INDEXER_ENABLED: z.enum(['true', 'false']).default('false'),

    ESCROW_INDEXER_STALE_THRESHOLD_SECONDS: z.coerce
      .number()
      .int()
      .min(ESCROW_INDEXER_STALE_THRESHOLD_SECONDS_MIN, {
        message: `ESCROW_INDEXER_STALE_THRESHOLD_SECONDS must be at least ${ESCROW_INDEXER_STALE_THRESHOLD_SECONDS_MIN}.`,
      })
      .default(300),

    ESCROW_READ_PROJECTION_ENABLED: z.enum(['true', 'false']).default('true'),
    INVOICE_STATE_ENABLED: z.enum(['true', 'false']).default('true'),
    CONFIG_RUNTIME_ENABLED: z.enum(['true', 'false']).default('true'),

    KYC_PROVIDER_URL: z.string().url().optional(),
    KYC_PROVIDER_API_KEY: z.string().min(1).optional(),
    KYC_PROVIDER_SECRET: z.string().min(1).optional(),

    KYC_PROVIDER_TIMEOUT_MS: z.coerce
      .number()
      .int()
      .min(KYC_TIMEOUT_MS_MIN, { message: `KYC_PROVIDER_TIMEOUT_MS must be at least ${KYC_TIMEOUT_MS_MIN} ms.` })
      .max(KYC_TIMEOUT_MS_MAX, { message: `KYC_PROVIDER_TIMEOUT_MS must be at most ${KYC_TIMEOUT_MS_MAX} ms.` })
      .default(5000),

    KYC_PROVIDER_MAX_RETRIES: z.coerce
      .number()
      .int()
      .min(KYC_MAX_RETRIES_MIN, { message: `KYC_PROVIDER_MAX_RETRIES must be at least ${KYC_MAX_RETRIES_MIN}.` })
      .max(KYC_MAX_RETRIES_MAX, { message: `KYC_PROVIDER_MAX_RETRIES must be at most ${KYC_MAX_RETRIES_MAX}.` })
      .default(3),

    KYC_PROVIDER_BASE_DELAY_MS: z.coerce
      .number()
      .int()
      .min(KYC_BASE_DELAY_MS_MIN, { message: `KYC_PROVIDER_BASE_DELAY_MS must be at least ${KYC_BASE_DELAY_MS_MIN} ms.` })
      .max(KYC_BASE_DELAY_MS_MAX, { message: `KYC_PROVIDER_BASE_DELAY_MS must be at most ${KYC_BASE_DELAY_MS_MAX} ms.` })
      .default(200),

    KYC_PROVIDER_MAX_DELAY_MS: z.coerce
      .number()
      .int()
      .min(KYC_MAX_DELAY_MS_MIN, { message: `KYC_PROVIDER_MAX_DELAY_MS must be at least ${KYC_MAX_DELAY_MS_MIN} ms.` })
      .max(KYC_MAX_DELAY_MS_MAX, { message: `KYC_PROVIDER_MAX_DELAY_MS must be at most ${KYC_MAX_DELAY_MS_MAX} ms.` })
      .default(5000),

    KYC_PROVIDER_SIGN_REQUESTS: z.enum(['true', 'false']).default('false'),
    KYC_PROVIDER_VERIFY_RESPONSE_SIGNATURE: z.enum(['true', 'false']).default('false'),

    KYC_PROVIDER_CB_FAILURE_THRESHOLD: z.coerce
      .number()
      .int()
      .min(KYC_CB_FAILURE_THRESHOLD_MIN, { message: `KYC_PROVIDER_CB_FAILURE_THRESHOLD must be at least ${KYC_CB_FAILURE_THRESHOLD_MIN}.` })
      .max(KYC_CB_FAILURE_THRESHOLD_MAX, { message: `KYC_PROVIDER_CB_FAILURE_THRESHOLD must be at most ${KYC_CB_FAILURE_THRESHOLD_MAX}.` })
      .default(5),

    KYC_PROVIDER_CB_RECOVERY_TIMEOUT_MS: z.coerce
      .number()
      .int()
      .min(KYC_CB_RECOVERY_TIMEOUT_MS_MIN, { message: `KYC_PROVIDER_CB_RECOVERY_TIMEOUT_MS must be at least ${KYC_CB_RECOVERY_TIMEOUT_MS_MIN} ms.` })
      .max(KYC_CB_RECOVERY_TIMEOUT_MS_MAX, { message: `KYC_PROVIDER_CB_RECOVERY_TIMEOUT_MS must be at most ${KYC_CB_RECOVERY_TIMEOUT_MS_MAX} ms.` })
      .default(10000),

    KYC_WEBHOOK_ENABLED: z.enum(['true', 'false']).default('false'),

    PUBLIC_API_BASE_URL: z.string().url().optional(),

    INVOICE_FILE_MAX_SIZE: InvoiceFileMaxSizeSchema,

    METRICS_ENABLED: z.enum(['true', 'false']).default('true'),
  })
  .superRefine((data, ctx) => {
    if (data.NODE_ENV === 'test') { return; }

    if (data.NODE_ENV === 'production' && !data.CURSOR_SECRET && !data.JWT_SECRET) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message: 'CURSOR_SECRET or JWT_SECRET must be configured in production.',
        path: ['CURSOR_SECRET'],
      });
    }

    const hasUrl = Boolean(data.KYC_PROVIDER_URL);
    const hasKey = Boolean(data.KYC_PROVIDER_API_KEY);
    if (hasUrl !== hasKey) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message: 'KYC_PROVIDER_URL and KYC_PROVIDER_API_KEY must both be set or both be absent.',
        path: hasUrl ? ['KYC_PROVIDER_API_KEY'] : ['KYC_PROVIDER_URL'],
      });
    }

    if (data.NODE_ENV === 'production') {
      const baseUrl = data.PUBLIC_API_BASE_URL;
      if (!baseUrl) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          message: 'PUBLIC_API_BASE_URL must be set in production. It is used in the OpenAPI spec servers array.',
          path: ['PUBLIC_API_BASE_URL'],
        });
        return;
      }
      let parsed;
      try { parsed = new URL(baseUrl); } catch (_) { parsed = null; }
      if (!parsed || parsed.protocol !== 'https:') {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          message: 'PUBLIC_API_BASE_URL must use HTTPS in production.',
          path: ['PUBLIC_API_BASE_URL'],
        });
        return;
      }
      const loopbackPattern = /^(localhost|127(?:\.\d+){3}|::1|\[::1\])$/i;
      if (loopbackPattern.test(parsed.hostname)) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          message: 'PUBLIC_API_BASE_URL must not be a loopback address in production.',
          path: ['PUBLIC_API_BASE_URL'],
        });
      }
    }
  });

// ─── Structured error class  (#1304) ──────────────────────────────────────────

/**
 * Structured error thrown by `validate()` and returned by `validateSafe()`.
 *
 * - `.code`   — always `'CONFIG_VALIDATION_ERROR'`; safe for programmatic handling.
 * - `.issues` — `{ path, message }[]`; key names and schema messages only, no secrets.
 * - `.cause`  — original ZodError for callers that need full Zod detail.
 */
class ConfigValidationError extends Error {
  constructor(zodError) {
    const summary = zodError.issues
      .map(i => `[${i.path.join('.')}]: ${i.message}`)
      .join('; ');
    super(`Configuration validation failed: ${summary}`);
    this.name = 'ConfigValidationError';
    this.code = 'CONFIG_VALIDATION_ERROR';
    this.issues = zodError.issues.map(i => ({
      path: i.path.join('.'),
      message: i.message,
    }));
    this.cause = zodError;
    if (Error.captureStackTrace) {
      Error.captureStackTrace(this, ConfigValidationError);
    }
  }
}

// ─── Singleton state  (#1303) ────────────────────────────────────────────────

/**
 * Runtime validated configuration object.
 * INVARIANT: once set, this is a deeply frozen object. Only replaced by a
 * successful validate(). A failed call never clears or partially overwrites it.
 * @type {Readonly<z.infer<typeof ConfigSchema>> | undefined}
 */
let config;

// ─── State helpers  (#1303) ──────────────────────────────────────────────────

/**
 * Returns true if validate() has succeeded at least once.
 * Allows graceful-degradation paths to check readiness without triggering the
 * guard error thrown by get().
 * @returns {boolean}
 */
function isValidated() {
  return config !== undefined;
}

/**
 * Resets the singleton to undefined. FOR TEST USE ONLY.
 * @returns {void}
 */
function _resetForTesting() {
  config = undefined;
}

// ─── Public API ───────────────────────────────────────────────────────────────

/**
 * Validates environment variables against the schema and returns a typed,
 * immutable config object.
 *
 * On success: singleton is replaced with a new deeply-frozen object.
 * On failure: singleton is left unchanged; throws ConfigValidationError.
 *
 * @returns {Readonly<z.infer<typeof ConfigSchema>>}
 * @throws {ConfigValidationError}
 */
function validate() {
  const parsed = ConfigSchema.safeParse(process.env);
  if (!parsed.success) {
    throw new ConfigValidationError(parsed.error);
  }
  config = Object.freeze(parsed.data);
  return config;
}

/**
 * Non-throwing variant of validate(). Returns a discriminated-union result.
 *
 * On failure the singleton is not modified — any previously-valid config survives.
 *
 * @returns {{ ok: true, config: Readonly<z.infer<typeof ConfigSchema>> } |
 *           { ok: false, error: ConfigValidationError }}
 */
function validateSafe() {
  try {
    const cfg = validate();
    return { ok: true, config: cfg };
  } catch (err) {
    const wrapped = err instanceof ConfigValidationError
      ? err
      : new ConfigValidationError(Object.assign(new Error(err.message), { issues: [] }));
    return { ok: false, error: wrapped };
  }
}

/**
 * Formats and logs a redacted summary of validation issues to console.error.
 * Accepts ConfigValidationError, ZodError, plain Error, null, or undefined.
 * Never prints raw environment variable values.
 *
 * @param {ConfigValidationError | z.ZodError | Error | null | undefined} error
 * @returns {void}
 */
function logRedactedSummary(error) {
  console.error('Configuration validation failed:');
  if (error instanceof ConfigValidationError) {
    error.issues.forEach(issue => {
      console.error(`- [${issue.path}]: ${issue.message}`);
    });
    return;
  }
  if (error && Array.isArray(error.issues)) {
    error.issues.forEach(issue => {
      const key = issue.path.join('.');
      console.error(`- [${key}]: ${issue.message}`);
    });
    return;
  }
  console.error(error ? error.message : 'Unknown configuration error');
}

/**
 * Returns the validated configuration singleton.
 * @throws {Error} If validate() has not been called successfully yet.
 * @returns {Readonly<z.infer<typeof ConfigSchema>>}
 */
function get() {
  if (!config) {
    throw new Error('Config not validated. Call validate() first.');
  }
  return config;
}

/**
 * Returns a single value from the validated configuration singleton.
 *
 * @template {keyof z.infer<typeof ConfigSchema>} K
 * @param {K} key
 * @returns {z.infer<typeof ConfigSchema>[K]}
 */
function getValue(key) {
  return get()[key];
}

/**
 * Returns the validated invoice PDF upload limit.
 * Falls back to "5mb" when the singleton is absent and env is missing/invalid.
 *
 * @returns {string} Express-compatible request size limit (e.g. "5mb").
 */
function getInvoiceFileMaxSize() {
  if (config) {
    return config.INVOICE_FILE_MAX_SIZE;
  }
  const result = InvoiceFileMaxSizeSchema.safeParse(process.env.INVOICE_FILE_MAX_SIZE);
  return result.success ? result.data : InvoiceFileMaxSizeSchema.parse(undefined);
}

/**
 * Returns the boolean value of a named feature flag from the validated config.
 *
 * Converts the stored "true"|"false" string to a native boolean.
 * Existing callers using getValue(key) === 'true' continue to work unchanged.
 *
 * @param {string} key - One of the keys in FEATURE_FLAG_KEYS.
 * @returns {boolean}
 * @throws {TypeError} If key is not a recognised feature-flag key.
 * @throws {Error} If validate() has not been called yet.
 */
function getFeatureFlag(key) {
  if (!FEATURE_FLAG_KEYS.includes(key)) {
    throw new TypeError(
      `"${key}" is not a valid feature-flag key. ` +
      `Valid keys: ${FEATURE_FLAG_KEYS.join(', ')}.`
    );
  }
  return getValue(key) === 'true';
}

// ─── Security headers ─────────────────────────────────────────────────────────

const securityHeaders = {
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'"],
      styleSrc: ["'self'"],
      imgSrc: ["'self'", "data:"],
      connectSrc: ["'self'"],
      fontSrc: ["'self'"],
      objectSrc: ["'none'"],
      mediaSrc: ["'self'"],
      frameSrc: ["'none'"],
      baseUri: ["'self'"],
      formAction: ["'self'"]
    }
  },
  referrerPolicy: { policy: 'no-referrer' },
  hsts: { maxAge: 31536000, includeSubDomains: true, preload: true },
  docsContentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'", "'unsafe-inline'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      imgSrc: ["'self'", "data:"],
      connectSrc: ["'self'"],
      fontSrc: ["'self'"],
      objectSrc: ["'none'"],
      mediaSrc: ["'self'"],
      frameSrc: ["'none'"],
      baseUri: ["'self'"],
      formAction: ["'self'"]
    }
  }
};

// ─── Exports ──────────────────────────────────────────────────────────────────

module.exports = {
  // Preserved (initial contract)
  validate,
  get,
  getValue,
  getInvoiceFileMaxSize,
  logRedactedSummary,
  ConfigSchema,
  InvoiceFileMaxSizeSchema,
  securityHeaders,
  // New — #1302
  VALIDATION_BOUNDARIES,
  // New — #1303
  isValidated,
  _resetForTesting,
  // New — #1304
  validateSafe,
  ConfigValidationError,
  // New — #1306
  getFeatureFlag,
  FEATURE_FLAG_KEYS,
  CONFIG_VERSION,
};
