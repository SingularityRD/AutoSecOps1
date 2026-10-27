/**
 * Global Zod configuration for the UI.
 *
 * Zod 4 changed the default English error messages. Many forms rely on Zod's
 * default messages (for example "Required" or "String must contain at least 1
 * character(s)"), so this module installs an error map that reproduces the
 * Zod 3 wording. Messages passed explicitly to a schema (`message` / `error`)
 * still take precedence, and issues this map does not recognise fall back to
 * Zod's own locale messages.
 *
 * It also enables `jitless` mode. Zod 4 otherwise probes `new Function(...)`
 * to JIT-compile object parsers, which the UI's CSP (no `unsafe-eval`) reports
 * as a violation. Zod 3 never evaluated code, so this keeps parity.
 *
 * Import this module for its side effect once per runtime (see
 * `ZodConfigInit` and `jest.setup.js`).
 */
import { z } from "zod"

type RawIssue = Parameters<NonNullable<z.core.$ZodConfig["customError"]>>[0]

/**
 * Returns the Zod 3 name for the runtime type of `data`.
 */
function getV3ParsedType(data: unknown): string {
  switch (typeof data) {
    case "undefined":
      return "undefined"
    case "string":
      return "string"
    case "number":
      return Number.isNaN(data) ? "nan" : "number"
    case "boolean":
      return "boolean"
    case "function":
      return "function"
    case "bigint":
      return "bigint"
    case "symbol":
      return "symbol"
    case "object":
      if (Array.isArray(data)) {
        return "array"
      }
      if (data === null) {
        return "null"
      }
      if (
        typeof (data as { then?: unknown }).then === "function" &&
        typeof (data as { catch?: unknown }).catch === "function"
      ) {
        return "promise"
      }
      if (typeof Map !== "undefined" && data instanceof Map) {
        return "map"
      }
      if (typeof Set !== "undefined" && data instanceof Set) {
        return "set"
      }
      if (typeof Date !== "undefined" && data instanceof Date) {
        return "date"
      }
      return "object"
    default:
      return "unknown"
  }
}

/**
 * Formats values the way Zod 3 `util.joinValues` did.
 */
function joinV3Values(values: readonly unknown[], separator = " | "): string {
  return values
    .map((value) => (typeof value === "string" ? `'${value}'` : String(value)))
    .join(separator)
}

function getSchemaType(issue: RawIssue): string | undefined {
  const inst = issue.inst as { _zod?: { def?: { type?: string } } } | undefined
  return inst?._zod?.def?.type
}

function formatTooSmall(
  origin: string,
  minimum: number | bigint,
  inclusive: boolean | undefined,
  exact: boolean | undefined
): string | undefined {
  switch (origin) {
    case "array":
    case "set": {
      const noun = origin === "array" ? "Array" : "Set"
      let qualifier = "more than"
      if (exact) {
        qualifier = "exactly"
      } else if (inclusive) {
        qualifier = "at least"
      }
      return `${noun} must contain ${qualifier} ${minimum} element(s)`
    }
    case "string": {
      let qualifier = "over"
      if (exact) {
        qualifier = "exactly"
      } else if (inclusive) {
        qualifier = "at least"
      }
      return `String must contain ${qualifier} ${minimum} character(s)`
    }
    case "number":
    case "int":
    case "bigint": {
      let qualifier = "greater than "
      if (exact) {
        qualifier = "exactly equal to "
      } else if (inclusive) {
        qualifier = "greater than or equal to "
      }
      return `Number must be ${qualifier}${minimum}`
    }
    case "date": {
      let qualifier = "greater than "
      if (exact) {
        qualifier = "exactly equal to "
      } else if (inclusive) {
        qualifier = "greater than or equal to "
      }
      return `Date must be ${qualifier}${new Date(Number(minimum))}`
    }
    default:
      return undefined
  }
}

function formatTooBig(
  origin: string,
  maximum: number | bigint,
  inclusive: boolean | undefined,
  exact: boolean | undefined
): string | undefined {
  switch (origin) {
    case "array":
    case "set": {
      const noun = origin === "array" ? "Array" : "Set"
      let qualifier = "less than"
      if (exact) {
        qualifier = "exactly"
      } else if (inclusive) {
        qualifier = "at most"
      }
      return `${noun} must contain ${qualifier} ${maximum} element(s)`
    }
    case "string": {
      let qualifier = "under"
      if (exact) {
        qualifier = "exactly"
      } else if (inclusive) {
        qualifier = "at most"
      }
      return `String must contain ${qualifier} ${maximum} character(s)`
    }
    case "number":
    case "int":
    case "bigint": {
      let qualifier = "less than"
      if (exact) {
        qualifier = "exactly"
      } else if (inclusive) {
        qualifier = "less than or equal to"
      }
      return `Number must be ${qualifier} ${maximum}`
    }
    case "date": {
      let qualifier = "smaller than "
      if (exact) {
        qualifier = "exactly "
      } else if (inclusive) {
        qualifier = "smaller than or equal to "
      }
      return `Date must be ${qualifier}${new Date(Number(maximum))}`
    }
    default:
      return undefined
  }
}

function formatInvalidValue(issue: RawIssue & { code: "invalid_value" }) {
  const schemaType = getSchemaType(issue)
  if (schemaType === "literal") {
    return `Invalid literal value, expected ${JSON.stringify(issue.values[0])}`
  }
  // Zod 3 enums reported non-string (or, for native enums, non-string and
  // non-number) input as a type error before checking membership.
  const input = issue.input
  const inputIsPrimitiveEnumValue =
    typeof input === "string" || typeof input === "number"
  if (!inputIsPrimitiveEnumValue) {
    if (input === undefined) {
      return "Required"
    }
    return `Expected ${joinV3Values(issue.values)}, received ${getV3ParsedType(input)}`
  }
  return `Invalid enum value. Expected ${joinV3Values(issue.values)}, received '${String(input)}'`
}

function formatInvalidFormat(
  issue: RawIssue & { code: "invalid_format" }
): string {
  const details = issue as unknown as {
    prefix?: string
    suffix?: string
    includes?: string
  }
  switch (issue.format) {
    case "regex":
      return "Invalid"
    case "starts_with":
      return `Invalid input: must start with "${details.prefix}"`
    case "ends_with":
      return `Invalid input: must end with "${details.suffix}"`
    case "includes":
      return `Invalid input: must include "${details.includes}"`
    case "guid":
      return "Invalid uuid"
    case "ipv4":
    case "ipv6":
      return "Invalid ip"
    case "cidrv4":
    case "cidrv6":
      return "Invalid cidr"
    default:
      return `Invalid ${issue.format}`
  }
}

/**
 * Zod error map that reproduces Zod 3's default English messages.
 *
 * @param issue Raw issue emitted by a Zod 4 schema.
 * @returns The Zod 3 message, or `undefined` to fall back to Zod's locale.
 */
export function zodV3CompatErrorMap(issue: RawIssue): string | undefined {
  switch (issue.code) {
    case "invalid_type": {
      // `z.instanceof(Class)` is a custom schema; Zod 3 reported it with a
      // fixed message regardless of the input.
      if (getSchemaType(issue) === "custom") {
        return `Input not instance of ${issue.expected}`
      }
      if (issue.input === undefined) {
        return "Required"
      }
      if (issue.expected === "int") {
        return `Expected integer, received ${
          typeof issue.input === "number" && !Number.isNaN(issue.input)
            ? "float"
            : getV3ParsedType(issue.input)
        }`
      }
      return `Expected ${issue.expected}, received ${getV3ParsedType(issue.input)}`
    }
    case "invalid_value":
      return formatInvalidValue(issue)
    case "too_small":
      return formatTooSmall(
        issue.origin,
        issue.minimum,
        issue.inclusive,
        issue.exact
      )
    case "too_big":
      return formatTooBig(
        issue.origin,
        issue.maximum,
        issue.inclusive,
        issue.exact
      )
    case "invalid_format":
      return formatInvalidFormat(issue)
    case "not_multiple_of":
      return `Number must be a multiple of ${issue.divisor}`
    case "unrecognized_keys":
      return `Unrecognized key(s) in object: ${issue.keys
        .map((key) => `'${key}'`)
        .join(", ")}`
    case "invalid_union": {
      const details = issue as unknown as {
        discriminator?: string
        options?: readonly unknown[]
        note?: string
      }
      if (details.note === "No matching discriminator" && details.options) {
        return `Invalid discriminator value. Expected ${joinV3Values(details.options)}`
      }
      return "Invalid input"
    }
    case "custom":
      return "Invalid input"
    default:
      return undefined
  }
}

z.config({ customError: zodV3CompatErrorMap, jitless: true })
