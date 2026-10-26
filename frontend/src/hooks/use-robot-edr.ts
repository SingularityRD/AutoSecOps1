"use client"

import {
  type CaseRead,
  type CaseReadMinimal,
  type CaseSearchRequest,
  casesGetCase,
  casesQueryCases,
  type RobotCreate,
  type RobotKeyCreate,
  type RobotKeyRead,
  type RobotRead,
  robotEdrCreateRobot,
  robotEdrCreateRobotKey,
  robotEdrGetRobot,
  robotEdrListRobotKeys,
  robotEdrListRobots,
  robotEdrRevokeRobotKey,
} from "@/client"
import { useMutation, useQuery, useQueryClient } from "@/lib/query"
import { hasRobodrTag } from "@/lib/robodr"

/** Page size used for every Robot EDR list call. */
const PAGE_LIMIT = 200
/** Pages read before a list is reported as truncated. */
const MAX_PAGES = 5

/** A list read across cursor pages, capped at {@link MAX_PAGES}. */
export interface CappedList<T> {
  items: T[]
  /** More items exist than were read. */
  truncated: boolean
}

async function readPages<T>(
  fetchPage: (
    cursor: string | null
  ) => Promise<{ items: T[]; next_cursor?: string | null }>
): Promise<CappedList<T>> {
  const items: T[] = []
  let cursor: string | null = null
  for (let page = 0; page < MAX_PAGES; page += 1) {
    const response = await fetchPage(cursor)
    items.push(...response.items)
    cursor = response.next_cursor ?? null
    if (!cursor) {
      return { items, truncated: false }
    }
  }
  return { items, truncated: true }
}

/** Query key root for everything on the Robots pages. */
export function robotEdrQueryKey(workspaceId: string) {
  return ["robot-edr", workspaceId] as const
}

/** Lists the workspace's registered robots. */
export function useRobots(
  workspaceId: string,
  { enabled = true }: { enabled?: boolean } = {}
) {
  return useQuery<CappedList<RobotRead>, Error>({
    queryKey: [...robotEdrQueryKey(workspaceId), "robots"],
    queryFn: async () =>
      await readPages((cursor) =>
        robotEdrListRobots({ workspaceId, limit: PAGE_LIMIT, cursor })
      ),
    enabled: enabled && Boolean(workspaceId),
    meta: { suppressErrorToast: true },
  })
}

/** Reads one registered robot by its AutoSecOps id. */
export function useRobot(
  workspaceId: string,
  robotId: string,
  { enabled = true }: { enabled?: boolean } = {}
) {
  return useQuery<RobotRead, Error>({
    queryKey: [...robotEdrQueryKey(workspaceId), "robots", robotId],
    queryFn: async () => await robotEdrGetRobot({ workspaceId, robotId }),
    enabled: enabled && Boolean(workspaceId && robotId),
    meta: { suppressErrorToast: true },
    retry: false,
  })
}

/**
 * Lists registered keys: every key in the workspace, or only the keys bound
 * to one robot when `robotId` (the AutoSecOps robot id) is given.
 */
export function useRobotKeys(
  workspaceId: string,
  {
    robotId,
    enabled = true,
  }: { robotId?: string | null; enabled?: boolean } = {}
) {
  return useQuery<CappedList<RobotKeyRead>, Error>({
    queryKey: [...robotEdrQueryKey(workspaceId), "keys", robotId ?? "all"],
    queryFn: async () =>
      await readPages((cursor) =>
        robotEdrListRobotKeys({
          workspaceId,
          robotId: robotId ?? null,
          limit: PAGE_LIMIT,
          cursor,
        })
      ),
    enabled: enabled && Boolean(workspaceId),
    meta: { suppressErrorToast: true },
  })
}

/** Registers a robot, then refreshes the robot list. */
export function useCreateRobot(workspaceId: string) {
  const queryClient = useQueryClient()
  return useMutation<RobotRead, Error, RobotCreate>({
    mutationFn: async (requestBody) =>
      await robotEdrCreateRobot({ workspaceId, requestBody }),
    onSuccess: () =>
      queryClient.invalidateQueries({
        queryKey: robotEdrQueryKey(workspaceId),
      }),
    meta: { suppressErrorToast: true },
  })
}

/** Registers a public key, then refreshes the key lists. */
export function useCreateRobotKey(workspaceId: string) {
  const queryClient = useQueryClient()
  return useMutation<RobotKeyRead, Error, RobotKeyCreate>({
    mutationFn: async (requestBody) =>
      await robotEdrCreateRobotKey({ workspaceId, requestBody }),
    onSuccess: () =>
      queryClient.invalidateQueries({
        queryKey: [...robotEdrQueryKey(workspaceId), "keys"],
      }),
    meta: { suppressErrorToast: true },
  })
}

/** Revokes a key by its AutoSecOps id, then refreshes the key lists. */
export function useRevokeRobotKey(workspaceId: string) {
  const queryClient = useQueryClient()
  return useMutation<RobotKeyRead, Error, string>({
    mutationFn: async (keyId) =>
      await robotEdrRevokeRobotKey({ workspaceId, keyId }),
    onSuccess: () =>
      queryClient.invalidateQueries({
        queryKey: [...robotEdrQueryKey(workspaceId), "keys"],
      }),
    meta: { suppressErrorToast: true },
  })
}

async function queryRobodrCases(
  workspaceId: string,
  request: CaseSearchRequest,
  maxPages: number
): Promise<CappedList<CaseReadMinimal>> {
  const items: CaseReadMinimal[] = []
  let cursor: string | null = null
  for (let page = 0; page < maxPages; page += 1) {
    const response = await casesQueryCases({
      workspaceId,
      requestBody: { ...request, cursor, limit: PAGE_LIMIT },
    })
    // The tag is checked here, not in the request: a tag filter on a
    // workspace that has never seen a RoboDR case is a 400.
    items.push(...response.items.filter((item) => hasRobodrTag(item.tags)))
    cursor = response.next_cursor ?? null
    if (!cursor) {
      return { items, truncated: false }
    }
  }
  return { items, truncated: true }
}

/**
 * Reads the most recently updated RoboDR cases of the workspace with only the
 * `robodr` payload projected, for the fleet statistics.
 */
export function useRobodrFleetCases(
  workspaceId: string,
  { enabled = true }: { enabled?: boolean } = {}
) {
  return useQuery<CappedList<CaseReadMinimal>, Error>({
    queryKey: [...robotEdrQueryKey(workspaceId), "fleet-cases"],
    queryFn: async () =>
      await queryRobodrCases(
        workspaceId,
        {
          filters: { not: { field: "payload.robodr.robot_id", op: "is_null" } },
          order_by: "updated_at",
          sort: "desc",
          payload_paths: [
            ["robodr", "robot_id"],
            ["robodr", "last_seen_ms"],
          ],
          include_count: false,
        },
        MAX_PAGES
      ),
    enabled: enabled && Boolean(workspaceId),
    meta: { suppressErrorToast: true },
  })
}

/** Reads the latest RoboDR cases of one robot, newest activity first. */
export function useRobotFindings(
  workspaceId: string,
  robodrRobotId: string | null | undefined,
  { enabled = true }: { enabled?: boolean } = {}
) {
  return useQuery<CappedList<CaseReadMinimal>, Error>({
    queryKey: [...robotEdrQueryKey(workspaceId), "findings", robodrRobotId],
    queryFn: async () =>
      await queryRobodrCases(
        workspaceId,
        {
          filters: {
            field: "payload.robodr.robot_id",
            op: "eq",
            value: robodrRobotId ?? "",
          },
          order_by: "updated_at",
          sort: "desc",
          payload_paths: [["robodr"]],
          include_count: false,
        },
        1
      ),
    enabled: enabled && Boolean(workspaceId && robodrRobotId),
    meta: { suppressErrorToast: true },
  })
}

/** Reads one full case, including its custom field values. */
export function useRobodrCase(
  workspaceId: string,
  caseId: string | null | undefined
) {
  return useQuery<CaseRead, Error>({
    queryKey: [...robotEdrQueryKey(workspaceId), "case", caseId],
    queryFn: async () =>
      await casesGetCase({ workspaceId, caseId: caseId ?? "" }),
    enabled: Boolean(workspaceId && caseId),
    meta: { suppressErrorToast: true },
  })
}
