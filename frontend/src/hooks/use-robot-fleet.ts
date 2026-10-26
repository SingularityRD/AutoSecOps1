"use client"

import {
  type FleetApprovalCreate,
  type FleetApprovalRead,
  type FleetOfferRead,
  type FleetOfferUpdate,
  type FleetRevocationCreate,
  type FleetRevocationRead,
  type FleetRingRead,
  type FleetRingUpdate,
  type FleetSocKeyCreate,
  type FleetSocKeyRead,
  type FleetTokenCreate,
  type FleetTokenIssued,
  type FleetTokenRead,
  type RobotFleetStatus,
  robotEdrActivateFleetSocKey,
  robotEdrApproveRobotProfile,
  robotEdrCancelRobotProfileApproval,
  robotEdrCreateFleetSocKey,
  robotEdrGetRobotFleetStatus,
  robotEdrIssueRobotEnrollmentToken,
  robotEdrListFleetRevocationLists,
  robotEdrListFleetSocKeys,
  robotEdrPublishFleetRevocationList,
  robotEdrRequestRobotProfileApproval,
  robotEdrRevokeRobotEnrollmentToken,
  robotEdrSetRobotProfileOffer,
  robotEdrSetRobotRing,
} from "@/client"
import { robotEdrQueryKey } from "@/hooks/use-robot-edr"
import { useMutation, useQuery, useQueryClient } from "@/lib/query"

/** Revocation lists read for the status view (newest first, one page). */
const REVOCATION_PAGE_LIMIT = 100

/** Query key of one robot's fleet lifecycle. */
export function robotFleetQueryKey(workspaceId: string, robotId: string) {
  return [...robotEdrQueryKey(workspaceId), "fleet", robotId] as const
}

/** Query key of the workspace's SOC keys and revocation lists. */
export function fleetWorkspaceQueryKey(workspaceId: string) {
  return [...robotEdrQueryKey(workspaceId), "fleet-workspace"] as const
}

/** Reads a robot's enrollment, tokens, rotations, profiles and ring. */
export function useRobotFleetStatus(
  workspaceId: string,
  robotId: string,
  { enabled = true }: { enabled?: boolean } = {}
) {
  return useQuery<RobotFleetStatus, Error>({
    queryKey: robotFleetQueryKey(workspaceId, robotId),
    queryFn: async () =>
      await robotEdrGetRobotFleetStatus({ workspaceId, robotId }),
    enabled: enabled && Boolean(workspaceId && robotId),
    meta: { suppressErrorToast: true },
  })
}

/** Lists the workspace's SOC fleet and approval keys. */
export function useFleetSocKeys(
  workspaceId: string,
  { enabled = true }: { enabled?: boolean } = {}
) {
  return useQuery<FleetSocKeyRead[], Error>({
    queryKey: [...fleetWorkspaceQueryKey(workspaceId), "soc-keys"],
    queryFn: async () => await robotEdrListFleetSocKeys({ workspaceId }),
    enabled: enabled && Boolean(workspaceId),
    meta: { suppressErrorToast: true },
  })
}

/** Lists the newest published revocation lists. */
export function useFleetRevocationLists(
  workspaceId: string,
  { enabled = true }: { enabled?: boolean } = {}
) {
  return useQuery<FleetRevocationRead[], Error>({
    queryKey: [...fleetWorkspaceQueryKey(workspaceId), "revocations"],
    queryFn: async () =>
      (
        await robotEdrListFleetRevocationLists({
          workspaceId,
          limit: REVOCATION_PAGE_LIMIT,
        })
      ).items,
    enabled: enabled && Boolean(workspaceId),
    meta: { suppressErrorToast: true },
  })
}

function useInvalidateFleet(workspaceId: string) {
  const queryClient = useQueryClient()
  return async () =>
    await queryClient.invalidateQueries({
      queryKey: robotEdrQueryKey(workspaceId),
    })
}

/** Generates (or imports) a SOC fleet or approval key. */
export function useCreateFleetSocKey(workspaceId: string) {
  const invalidate = useInvalidateFleet(workspaceId)
  return useMutation<FleetSocKeyRead, Error, FleetSocKeyCreate>({
    mutationFn: async (requestBody) =>
      await robotEdrCreateFleetSocKey({ workspaceId, requestBody }),
    onSuccess: invalidate,
    meta: { suppressErrorToast: true },
  })
}

/** Switches signing to a pending SOC key. */
export function useActivateFleetSocKey(workspaceId: string) {
  const invalidate = useInvalidateFleet(workspaceId)
  return useMutation<FleetSocKeyRead, Error, string>({
    mutationFn: async (keyId) =>
      await robotEdrActivateFleetSocKey({ workspaceId, keyId }),
    onSuccess: invalidate,
    meta: { suppressErrorToast: true },
  })
}

/**
 * Issues a single-use enrollment token. The response is the only place the
 * token appears: it is never cached in the query client.
 */
export function useIssueEnrollmentToken(workspaceId: string, robotId: string) {
  const invalidate = useInvalidateFleet(workspaceId)
  return useMutation<FleetTokenIssued, Error, FleetTokenCreate>({
    mutationFn: async (requestBody) =>
      await robotEdrIssueRobotEnrollmentToken({
        workspaceId,
        robotId,
        requestBody,
      }),
    onSuccess: invalidate,
    meta: { suppressErrorToast: true },
  })
}

/** Revokes an unused enrollment token. */
export function useRevokeEnrollmentToken(workspaceId: string, robotId: string) {
  const invalidate = useInvalidateFleet(workspaceId)
  return useMutation<FleetTokenRead, Error, string>({
    mutationFn: async (tokenId) =>
      await robotEdrRevokeRobotEnrollmentToken({
        workspaceId,
        robotId,
        tokenId,
      }),
    onSuccess: invalidate,
    meta: { suppressErrorToast: true },
  })
}

/** Offers a locked, signed profile to the robot. */
export function useSetProfileOffer(workspaceId: string, robotId: string) {
  const invalidate = useInvalidateFleet(workspaceId)
  return useMutation<FleetOfferRead, Error, FleetOfferUpdate>({
    mutationFn: async (requestBody) =>
      await robotEdrSetRobotProfileOffer({ workspaceId, robotId, requestBody }),
    onSuccess: invalidate,
    meta: { suppressErrorToast: true },
  })
}

/** First sign-off: requests the observe to enforce approval. */
export function useRequestProfileApproval(
  workspaceId: string,
  robotId: string
) {
  const invalidate = useInvalidateFleet(workspaceId)
  return useMutation<FleetApprovalRead, Error, FleetApprovalCreate>({
    mutationFn: async (requestBody) =>
      await robotEdrRequestRobotProfileApproval({
        workspaceId,
        robotId,
        requestBody,
      }),
    onSuccess: invalidate,
    meta: { suppressErrorToast: true },
  })
}

/** Second sign-off by another user: signs the approval. */
export function useApproveProfile(workspaceId: string, robotId: string) {
  const invalidate = useInvalidateFleet(workspaceId)
  return useMutation<FleetApprovalRead, Error, string>({
    mutationFn: async (approvalId) =>
      await robotEdrApproveRobotProfile({ workspaceId, robotId, approvalId }),
    onSuccess: invalidate,
    meta: { suppressErrorToast: true },
  })
}

/** Withdraws an approval; a signed one is no longer served to the robot. */
export function useCancelProfileApproval(workspaceId: string, robotId: string) {
  const invalidate = useInvalidateFleet(workspaceId)
  return useMutation<FleetApprovalRead, Error, string>({
    mutationFn: async (approvalId) =>
      await robotEdrCancelRobotProfileApproval({
        workspaceId,
        robotId,
        approvalId,
      }),
    onSuccess: invalidate,
    meta: { suppressErrorToast: true },
  })
}

/** Publishes the robot's next update-ring document. */
export function useSetRobotRing(workspaceId: string, robotId: string) {
  const invalidate = useInvalidateFleet(workspaceId)
  return useMutation<FleetRingRead, Error, FleetRingUpdate>({
    mutationFn: async (requestBody) =>
      await robotEdrSetRobotRing({ workspaceId, robotId, requestBody }),
    onSuccess: invalidate,
    meta: { suppressErrorToast: true },
  })
}

/** Publishes a root-signed revocation list. */
export function usePublishRevocationList(workspaceId: string) {
  const invalidate = useInvalidateFleet(workspaceId)
  return useMutation<FleetRevocationRead, Error, FleetRevocationCreate>({
    mutationFn: async (requestBody) =>
      await robotEdrPublishFleetRevocationList({ workspaceId, requestBody }),
    onSuccess: invalidate,
    meta: { suppressErrorToast: true },
  })
}
