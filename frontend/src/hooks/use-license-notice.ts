"use client"

import {
  type LicenseNoticeRead,
  organizationGetOrganizationLicenseNotice,
} from "@/client"
import { useScopeCheck } from "@/components/auth/scope-guard"
import { useQuery } from "@/lib/query"

const LICENSE_NOTICE_STALE_TIME_MS = 15 * 60 * 1000

/**
 * Fetch the license expiry notice for organization administrators.
 *
 * Only users who can update organization settings query the notice, so other
 * members never trigger the request.
 */
export function useLicenseNotice(): {
  notice: LicenseNoticeRead | undefined
} {
  const canAdministerOrg = useScopeCheck("org:settings:update")
  const { data } = useQuery<LicenseNoticeRead>({
    queryKey: ["organization", "license-notice"],
    queryFn: organizationGetOrganizationLicenseNotice,
    enabled: canAdministerOrg === true,
    staleTime: LICENSE_NOTICE_STALE_TIME_MS,
    retry: false,
    // The banner is advisory; a failed check must not interrupt the user.
    meta: { suppressErrorToast: true },
  })
  return { notice: canAdministerOrg === true ? data : undefined }
}
