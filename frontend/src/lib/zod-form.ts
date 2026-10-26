import { zodResolver } from "@hookform/resolvers/zod"
import type { FieldValues, Resolver } from "react-hook-form"
import type { z } from "zod"

/**
 * Resolver whose field values and submitted values both use the schema's
 * parsed (output) shape.
 */
export type ZodOutputResolver<
  TSchema extends z.ZodType<FieldValues, FieldValues>,
> = Resolver<z.output<TSchema>, unknown, z.output<TSchema>>

/**
 * Builds a react-hook-form resolver for forms whose state is always held in
 * the schema's parsed (output) shape.
 *
 * With Zod 4, `zodResolver` types the form's field values with `z.input`, so
 * every field that has a `.default()` becomes optional. Forms that seed every
 * field through `defaultValues` and read their state as fully populated values
 * use this helper to keep `z.output` as the field value type, which matches
 * how these forms were typed with Zod 3. Validation is unchanged: values are
 * still parsed by the schema, and schema defaults still fill missing fields.
 *
 * @param schema Zod object schema that validates the form.
 * @returns A resolver typed with the schema output for both generics.
 */
export function zodOutputResolver<
  TSchema extends z.ZodType<FieldValues, FieldValues>,
>(schema: TSchema): ZodOutputResolver<TSchema> {
  return zodResolver(schema) as unknown as ZodOutputResolver<TSchema>
}
