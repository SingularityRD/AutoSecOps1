import type {
  JSONSchema7,
  JSONSchema7Definition,
  JSONSchema7Type,
} from "json-schema"
import type { EditorComponent } from "@/client"

/* expression component */

export type ExpressionComponent = {
  component_id: "expression"
}

export type AutoSecOpsEditorComponent = EditorComponent | ExpressionComponent
export type AutoSecOpsComponentId = NonNullable<
  AutoSecOpsEditorComponent["component_id"]
>

export type AutoSecOpsJsonSchema = JSONSchema7 & TcJsonSchemaExtra
export type AutoSecOpsJsonSchemaDefinition = JSONSchema7Definition &
  TcJsonSchemaExtra
export type AutoSecOpsJsonSchemaType = JSONSchema7Type & TcJsonSchemaExtra
export const AUTOSECOPS_COMPONENT_KEY = "x-autosecops-component" as const

export type TcJsonSchemaExtra = {
  [AUTOSECOPS_COMPONENT_KEY]?: AutoSecOpsEditorComponent[]
  deprecated?: boolean
  "x-autosecops-deprecation-message"?: string
}

export function isAutoSecOpsJsonSchema(
  schema: unknown
): schema is AutoSecOpsJsonSchema {
  return (
    typeof schema === "object" &&
    schema !== null &&
    AUTOSECOPS_COMPONENT_KEY in schema
  )
}

// Helper function to get components as array
/**
 * Returns the AutoSecOps components array from the schema.
 * If the component key is not present or not an array, returns an empty array.
 * Only returns the value if it is an array.
 *
 * @param schema - The AutoSecOpsJsonSchema object to extract components from.
 * @returns An array of component objects with at least a component_id.
 */
/**
 * Type guard to check if an object is a valid AutoSecOps component.
 * A valid component must be a non-null object with a string 'component_id' property.
 *
 * @param item - The item to check.
 * @returns True if the item is a valid AutoSecOps component, false otherwise.
 */
export function isAutoSecOpsComponent(
  item: unknown
): item is AutoSecOpsEditorComponent {
  return (
    typeof item === "object" &&
    item !== null &&
    "component_id" in item &&
    typeof (item as { component_id: unknown }).component_id === "string"
  )
}

/**
 * Returns the AutoSecOps components array from the schema.
 * If the component key is not present or not an array, returns an empty array.
 * Only returns the value if it is an array of valid AutoSecOps components.
 *
 * @param schema - The AutoSecOpsJsonSchema object to extract components from.
 * @returns An array of component objects with at least a component_id.
 */
export function getAutoSecOpsComponents(
  schema: AutoSecOpsJsonSchema
): AutoSecOpsEditorComponent[] {
  const component = schema[AUTOSECOPS_COMPONENT_KEY]
  if (Array.isArray(component)) {
    // Use the type guard to filter valid components
    return component.filter(isAutoSecOpsComponent)
  }
  return []
}

// Helper function to check if schema has multiple components
export function hasMultipleComponents(schema: AutoSecOpsJsonSchema): boolean {
  const component = schema[AUTOSECOPS_COMPONENT_KEY]
  return Array.isArray(component) && component.length > 1
}
