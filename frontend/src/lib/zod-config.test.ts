import { z } from "zod"
import "@/lib/zod-config"

function firstMessage(schema: z.ZodType, input: unknown): string | undefined {
  const result = schema.safeParse(input)
  if (result.success) {
    return undefined
  }
  return result.error.issues[0]?.message
}

describe("zod-config error map", () => {
  it("reports missing values as required", () => {
    expect(firstMessage(z.object({ name: z.string() }), {})).toBe("Required")
    expect(firstMessage(z.enum(["a", "b"]), undefined)).toBe("Required")
  })

  it("keeps Zod 3 type mismatch wording", () => {
    expect(firstMessage(z.string(), 1)).toBe("Expected string, received number")
    expect(firstMessage(z.number(), Number.NaN)).toBe(
      "Expected number, received nan"
    )
    expect(firstMessage(z.number().int(), 1.5)).toBe(
      "Expected integer, received float"
    )
    expect(firstMessage(z.instanceof(Date), "x")).toBe(
      "Input not instance of Date"
    )
  })

  it("keeps Zod 3 size wording", () => {
    expect(firstMessage(z.string().min(2), "a")).toBe(
      "String must contain at least 2 character(s)"
    )
    expect(firstMessage(z.string().max(1), "ab")).toBe(
      "String must contain at most 1 character(s)"
    )
    expect(firstMessage(z.string().length(2), "a")).toBe(
      "String must contain exactly 2 character(s)"
    )
    expect(firstMessage(z.array(z.string()).nonempty(), [])).toBe(
      "Array must contain at least 1 element(s)"
    )
    expect(firstMessage(z.number().min(1), 0)).toBe(
      "Number must be greater than or equal to 1"
    )
    expect(firstMessage(z.number().positive(), 0)).toBe(
      "Number must be greater than 0"
    )
    expect(firstMessage(z.number().max(3), 4)).toBe(
      "Number must be less than or equal to 3"
    )
  })

  it("keeps Zod 3 format and value wording", () => {
    expect(firstMessage(z.string().email(), "nope")).toBe("Invalid email")
    expect(firstMessage(z.string().url(), "nope")).toBe("Invalid url")
    expect(firstMessage(z.string().guid(), "nope")).toBe("Invalid uuid")
    expect(firstMessage(z.string().regex(/^a$/), "b")).toBe("Invalid")
    expect(firstMessage(z.enum(["a", "b"]), "c")).toBe(
      "Invalid enum value. Expected 'a' | 'b', received 'c'"
    )
    expect(firstMessage(z.literal("a"), "b")).toBe(
      'Invalid literal value, expected "a"'
    )
    expect(
      firstMessage(
        z.string().refine(() => false),
        "a"
      )
    ).toBe("Invalid input")
  })

  it("prefers messages passed to the schema", () => {
    expect(firstMessage(z.string().min(1, "Name is required"), "")).toBe(
      "Name is required"
    )
    expect(
      firstMessage(z.coerce.number({ error: "Must be a number" }), "x")
    ).toBe("Must be a number")
  })
})
