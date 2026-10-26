"use client"

import { type FormEvent, useId, useState } from "react"
import type { FleetApprovalRead, FleetTokenIssued } from "@/client"
import { CopyButton } from "@/components/copy-button"
import { AlertNotification } from "@/components/notifications"
import { Button } from "@/components/ui/button"
import {
  Dialog,
  DialogBody,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select"
import { Textarea } from "@/components/ui/textarea"
import { toast } from "@/components/ui/use-toast"
import {
  useAddFleetTrustRoot,
  useCreateFleetSocKey,
  useIssueEnrollmentToken,
  usePublishRevocationList,
  useSetProfileOffer,
  useSetRobotRing,
  useSubmitApprovalSignature,
} from "@/hooks/use-robot-fleet"
import { getApiErrorDetail } from "@/lib/errors"

const ENROLL_FORM_ID = "robot-enroll-form"
const OFFER_FORM_ID = "robot-profile-offer-form"
const RING_FORM_ID = "robot-ring-form"
const REVOCATION_FORM_ID = "robot-revocation-form"
const APPROVAL_KEY_FORM_ID = "robot-approval-key-form"
const SIGNATURE_FORM_ID = "robot-approval-signature-form"
const TRUST_ROOT_FORM_ID = "robot-trust-root-form"
const SIGNATURE_HEX_PATTERN = /^[0-9a-f]{128}$/

/** Token validity choices, in hours (the contract caps tokens at 7 days). */
export const TOKEN_VALIDITY_HOURS = [1, 24, 72, 168] as const

/** Version pattern of ring documents (`robodr.fleet` §7). */
export const FLEET_VERSION_PATTERN = /^[0-9][0-9A-Za-z.+~-]{0,63}$/
const SHA256_HEX_PATTERN = /^[0-9a-f]{64}$/

function validityLabel(hours: number): string {
  if (hours < 24) {
    return `${hours} hour${hours === 1 ? "" : "s"}`
  }
  const days = hours / 24
  return `${days} day${days === 1 ? "" : "s"}`
}

function failed(title: string, err: unknown) {
  toast({
    title,
    description: getApiErrorDetail(err) ?? undefined,
    variant: "destructive",
  })
}

/** Props for {@link EnrollRobotDialog}. */
export interface EnrollRobotDialogProps {
  workspaceId: string
  /** AutoSecOps robot id (UUID). */
  robotId: string
  robodrRobotId: string
  open: boolean
  onOpenChange: (open: boolean) => void
}

/**
 * Issues a single-use enrollment token and shows it once. The token lives
 * only in this dialog's state and is dropped when the dialog closes.
 */
export function EnrollRobotDialog({
  workspaceId,
  robotId,
  robodrRobotId,
  open,
  onOpenChange,
}: EnrollRobotDialogProps) {
  const fieldId = useId()
  const issue = useIssueEnrollmentToken(workspaceId, robotId)
  const [validity, setValidity] = useState<string>("24")
  const [issued, setIssued] = useState<FleetTokenIssued | null>(null)

  async function handleSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    try {
      setIssued(await issue.mutateAsync({ validity_hours: Number(validity) }))
    } catch (err) {
      failed("Failed to issue enrollment token", err)
    }
  }

  return (
    <Dialog
      open={open}
      onOpenChange={(next) => {
        if (!next) {
          // Drop the token from the dialog and from the mutation cache.
          setIssued(null)
          issue.reset()
          setValidity("24")
        }
        onOpenChange(next)
      }}
    >
      <DialogContent size="md">
        <DialogHeader>
          <DialogTitle>Enroll robot</DialogTitle>
          <DialogDescription>
            Issue a single-use token for {robodrRobotId}. The robot generates
            its keys and enrolls with robodr-enroll.
          </DialogDescription>
        </DialogHeader>
        <DialogBody>
          {issued ? (
            <div className="space-y-4">
              <AlertNotification
                level="warning"
                message="This token is shown once. It is a credential until the robot uses it: hand it over on a root-only file or standard input, never on the command line."
              />
              <div className="space-y-2">
                <div className="flex items-center justify-between">
                  <Label htmlFor={`${fieldId}-token`}>Enrollment token</Label>
                  <CopyButton
                    value={issued.token}
                    toastMessage="Enrollment token copied"
                    tooltipMessage="Copy token"
                  />
                </div>
                <Textarea
                  id={`${fieldId}-token`}
                  readOnly
                  value={issued.token}
                  className="h-28 resize-none break-all font-mono text-xs"
                  onFocus={(event) => event.currentTarget.select()}
                />
              </div>
              <dl className="grid grid-cols-[120px_minmax(0,1fr)] gap-2 text-xs">
                <dt className="text-muted-foreground">Token id</dt>
                <dd className="font-mono">{issued.token_id}</dd>
                <dt className="text-muted-foreground">Expires</dt>
                <dd>{new Date(issued.expires_at).toLocaleString()}</dd>
                <dt className="text-muted-foreground">Site</dt>
                <dd>{issued.site ?? "—"}</dd>
                <dt className="text-muted-foreground">Signed by</dt>
                <dd className="font-mono">{issued.soc_key_id}</dd>
              </dl>
            </div>
          ) : (
            <form
              id={ENROLL_FORM_ID}
              className="space-y-4"
              onSubmit={handleSubmit}
            >
              <div className="space-y-2">
                <Label htmlFor={`${fieldId}-validity`}>Valid for</Label>
                <Select value={validity} onValueChange={setValidity}>
                  <SelectTrigger id={`${fieldId}-validity`}>
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    {TOKEN_VALIDITY_HOURS.map((hours) => (
                      <SelectItem key={hours} value={String(hours)}>
                        {validityLabel(hours)}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
                <p className="text-xs text-muted-foreground">
                  An air-gapped enrollment must reach the SOC within this time.
                </p>
              </div>
            </form>
          )}
        </DialogBody>
        <DialogFooter>
          {issued ? null : (
            <Button
              size="sm"
              type="submit"
              form={ENROLL_FORM_ID}
              disabled={issue.isPending}
            >
              Issue token
            </Button>
          )}
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}

/** Props for the robot-scoped fleet dialogs. */
export interface RobotFleetDialogProps {
  workspaceId: string
  robotId: string
  open: boolean
  onOpenChange: (open: boolean) => void
}

/** Offers a locked, signed profile (robodr-commission output) to the robot. */
export function OfferProfileDialog({
  workspaceId,
  robotId,
  open,
  onOpenChange,
}: RobotFleetDialogProps) {
  const fieldId = useId()
  const setOffer = useSetProfileOffer(workspaceId, robotId)
  const [profile, setProfile] = useState("")
  const [signature, setSignature] = useState("")

  async function handleSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    try {
      const offer = await setOffer.mutateAsync({ profile, signature })
      toast({
        title: "Profile offered",
        description: `Version ${offer.profile_version} for ${offer.platform}`,
      })
      setProfile("")
      setSignature("")
      onOpenChange(false)
    } catch (err) {
      failed("Failed to offer profile", err)
    }
  }

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent size="lg">
        <DialogHeader>
          <DialogTitle>Offer profile</DialogTitle>
          <DialogDescription>
            The robot stages the profile; it is enforced only after a two-person
            approval and a local install.
          </DialogDescription>
        </DialogHeader>
        <DialogBody>
          <form
            id={OFFER_FORM_ID}
            className="space-y-4"
            onSubmit={handleSubmit}
          >
            <div className="space-y-2">
              <Label htmlFor={`${fieldId}-profile`}>Locked profile file</Label>
              <Textarea
                id={`${fieldId}-profile`}
                value={profile}
                onChange={(event) => setProfile(event.target.value)}
                className="min-h-[180px] font-mono text-xs"
                required
              />
            </div>
            <div className="space-y-2">
              <Label htmlFor={`${fieldId}-sig`}>Signature file (.sig)</Label>
              <Textarea
                id={`${fieldId}-sig`}
                value={signature}
                onChange={(event) => setSignature(event.target.value)}
                className="min-h-[100px] font-mono text-xs"
                required
              />
            </div>
          </form>
        </DialogBody>
        <DialogFooter>
          <Button
            size="sm"
            type="submit"
            form={OFFER_FORM_ID}
            disabled={setOffer.isPending || !profile || !signature}
          >
            Offer profile
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}

/** Publishes the robot's next update-ring document (information only). */
export function SetRingDialog({
  workspaceId,
  robotId,
  open,
  onOpenChange,
}: RobotFleetDialogProps) {
  const fieldId = useId()
  const setRing = useSetRobotRing(workspaceId, robotId)
  const [ring, setRingValue] = useState("2")
  const [targetVersion, setTargetVersion] = useState("")
  const [bundle, setBundle] = useState("")
  const [minVersion, setMinVersion] = useState("")
  const [error, setError] = useState<string | null>(null)

  async function handleSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    const target = targetVersion.trim() || null
    const floor = minVersion.trim() || null
    const sha = bundle.trim().toLowerCase() || null
    if (
      (target && !FLEET_VERSION_PATTERN.test(target)) ||
      (floor && !FLEET_VERSION_PATTERN.test(floor))
    ) {
      setError("Versions start with a digit, e.g. 0.3.0.")
      return
    }
    if (sha && !SHA256_HEX_PATTERN.test(sha)) {
      setError("The bundle SHA-256 is 64 hex digits.")
      return
    }
    setError(null)
    try {
      const published = await setRing.mutateAsync({
        ring: Number(ring),
        target_version: target,
        bundle_sha256: sha,
        min_version: floor,
      })
      toast({
        title: "Ring published",
        description: `Serial ${published.serial}`,
      })
      onOpenChange(false)
    } catch (err) {
      failed("Failed to publish ring", err)
    }
  }

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent size="md">
        <DialogHeader>
          <DialogTitle>Set update ring</DialogTitle>
          <DialogDescription>
            Information only: the robot never downloads or installs anything
            from it. The minimum version raises its security floor.
          </DialogDescription>
        </DialogHeader>
        <DialogBody>
          <form id={RING_FORM_ID} className="space-y-4" onSubmit={handleSubmit}>
            <div className="space-y-2">
              <Label htmlFor={`${fieldId}-ring`}>Ring</Label>
              <Select value={ring} onValueChange={setRingValue}>
                <SelectTrigger id={`${fieldId}-ring`}>
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="0">0 · Canary</SelectItem>
                  <SelectItem value="1">1 · Early</SelectItem>
                  <SelectItem value="2">2 · Broad</SelectItem>
                </SelectContent>
              </Select>
            </div>
            <div className="space-y-2">
              <Label htmlFor={`${fieldId}-target`}>Target version</Label>
              <Input
                id={`${fieldId}-target`}
                value={targetVersion}
                onChange={(event) => setTargetVersion(event.target.value)}
                placeholder="0.3.0"
              />
            </div>
            <div className="space-y-2">
              <Label htmlFor={`${fieldId}-bundle`}>Bundle SHA-256</Label>
              <Input
                id={`${fieldId}-bundle`}
                value={bundle}
                onChange={(event) => setBundle(event.target.value)}
                className="font-mono text-xs"
              />
            </div>
            <div className="space-y-2">
              <Label htmlFor={`${fieldId}-min`}>Minimum version</Label>
              <Input
                id={`${fieldId}-min`}
                value={minVersion}
                onChange={(event) => setMinVersion(event.target.value)}
                placeholder="Lowest release the robot may run"
              />
            </div>
            {error ? (
              <p role="alert" className="text-xs text-destructive">
                {error}
              </p>
            ) : null}
          </form>
        </DialogBody>
        <DialogFooter>
          <Button
            size="sm"
            type="submit"
            form={RING_FORM_ID}
            disabled={setRing.isPending}
          >
            Publish
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}

/** Props for {@link PublishRevocationListDialog}. */
export interface PublishRevocationListDialogProps {
  workspaceId: string
  open: boolean
  onOpenChange: (open: boolean) => void
}

/** Publishes a root-signed `robodr-profile-revocations/v2` list. */
export function PublishRevocationListDialog({
  workspaceId,
  open,
  onOpenChange,
}: PublishRevocationListDialogProps) {
  const fieldId = useId()
  const publish = usePublishRevocationList(workspaceId)
  const [list, setList] = useState("")

  async function handleSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    try {
      const published = await publish.mutateAsync({ revocation_list: list })
      toast({
        title: "Revocation list published",
        description: `${published.platform} serial ${published.serial}`,
      })
      setList("")
      onOpenChange(false)
    } catch (err) {
      failed("Failed to publish revocation list", err)
    }
  }

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent size="lg">
        <DialogHeader>
          <DialogTitle>Publish revocation list</DialogTitle>
          <DialogDescription>
            A list signed offline by one of the workspace's trust roots; others
            are refused. The serial of a platform only rises.
          </DialogDescription>
        </DialogHeader>
        <DialogBody>
          <form
            id={REVOCATION_FORM_ID}
            className="space-y-4"
            onSubmit={handleSubmit}
          >
            <div className="space-y-2">
              <Label htmlFor={`${fieldId}-list`}>Revocation list file</Label>
              <Textarea
                id={`${fieldId}-list`}
                value={list}
                onChange={(event) => setList(event.target.value)}
                className="min-h-[180px] font-mono text-xs"
                required
              />
            </div>
          </form>
        </DialogBody>
        <DialogFooter>
          <Button
            size="sm"
            type="submit"
            form={REVOCATION_FORM_ID}
            disabled={publish.isPending || !list}
          >
            Publish
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}

/** Props for the workspace-scoped fleet key dialogs. */
export interface FleetWorkspaceDialogProps {
  workspaceId: string
  open: boolean
  onOpenChange: (open: boolean) => void
}

/**
 * Registers an offline approval key by its public key file. The secret stays
 * with the operator who signs prepared approvals; a second user activates it.
 */
export function RegisterApprovalKeyDialog({
  workspaceId,
  open,
  onOpenChange,
}: FleetWorkspaceDialogProps) {
  const fieldId = useId()
  const createKey = useCreateFleetSocKey(workspaceId)
  const [publicKeyFile, setPublicKeyFile] = useState("")

  async function handleSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    try {
      const created = await createKey.mutateAsync({
        kind: "approval",
        custody: "offline",
        public_key_file: publicKeyFile.trim(),
      })
      toast({
        title: "Approval key registered",
        description: `${created.key_id} waits for a second user to activate it.`,
      })
      setPublicKeyFile("")
      onOpenChange(false)
    } catch (err) {
      failed("Failed to register approval key", err)
    }
  }

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent size="md">
        <DialogHeader>
          <DialogTitle>Register offline approval key</DialogTitle>
          <DialogDescription>
            Paste the public key file of the approval key you hold offline or in
            an HSM. AutoSecOps never sees its secret.
          </DialogDescription>
        </DialogHeader>
        <DialogBody>
          <form
            id={APPROVAL_KEY_FORM_ID}
            className="space-y-2"
            onSubmit={handleSubmit}
          >
            <Label htmlFor={`${fieldId}-public`}>Public key file</Label>
            <Textarea
              id={`${fieldId}-public`}
              value={publicKeyFile}
              onChange={(event) => setPublicKeyFile(event.target.value)}
              className="min-h-[120px] font-mono text-xs"
              placeholder="robodr-blackbox-key/v2 .pub file or 64 hex digits"
              required
            />
          </form>
        </DialogBody>
        <DialogFooter>
          <Button
            size="sm"
            type="submit"
            form={APPROVAL_KEY_FORM_ID}
            disabled={createKey.isPending || !publicKeyFile.trim()}
          >
            Register
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}

/** Props for {@link SignApprovalDialog}. */
export interface SignApprovalDialogProps extends RobotFleetDialogProps {
  /** The prepared approval to sign; the dialog is closed when null. */
  approval: FleetApprovalRead | null
}

/**
 * Shows the exact bytes the offline approval key signs and accepts the
 * detached Ed25519 signature.
 */
export function SignApprovalDialog({
  workspaceId,
  robotId,
  approval,
  open,
  onOpenChange,
}: SignApprovalDialogProps) {
  const fieldId = useId()
  const submit = useSubmitApprovalSignature(workspaceId, robotId)
  const [signature, setSignature] = useState("")
  const valid = SIGNATURE_HEX_PATTERN.test(signature.trim())

  async function handleSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    if (!approval || !valid) {
      return
    }
    try {
      await submit.mutateAsync({
        approvalId: approval.id,
        requestBody: { signature: signature.trim() },
      })
      toast({
        title: "Approval signed",
        description: "The robot can fetch the approval now.",
      })
      setSignature("")
      onOpenChange(false)
    } catch (err) {
      failed("Failed to attach the signature", err)
    }
  }

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent size="lg">
        <DialogHeader>
          <DialogTitle>Sign approval</DialogTitle>
          <DialogDescription>
            Sign the message with the offline approval key{" "}
            {approval?.signer_key_id ?? ""} (Ed25519) and paste the signature.
          </DialogDescription>
        </DialogHeader>
        <DialogBody>
          <form
            id={SIGNATURE_FORM_ID}
            className="space-y-4"
            onSubmit={handleSubmit}
          >
            <div className="space-y-2">
              <div className="flex items-center justify-between">
                <Label htmlFor={`${fieldId}-message`}>Message to sign</Label>
                <CopyButton
                  value={approval?.signing_message_hex ?? ""}
                  toastMessage="Message copied"
                  tooltipMessage="Copy the message (hex)"
                />
              </div>
              <Textarea
                id={`${fieldId}-message`}
                readOnly
                value={approval?.signing_message_hex ?? ""}
                className="h-24 resize-none break-all font-mono text-xs"
              />
            </div>
            <div className="space-y-2">
              <Label htmlFor={`${fieldId}-payload`}>Approval payload</Label>
              <Textarea
                id={`${fieldId}-payload`}
                readOnly
                value={approval?.signing_payload ?? ""}
                className="h-24 resize-none break-all font-mono text-xs"
              />
            </div>
            <div className="space-y-2">
              <Label htmlFor={`${fieldId}-signature`}>Signature</Label>
              <Input
                id={`${fieldId}-signature`}
                value={signature}
                onChange={(event) => setSignature(event.target.value)}
                className="font-mono text-xs"
                placeholder="128 lower-case hex digits"
                required
              />
            </div>
          </form>
        </DialogBody>
        <DialogFooter>
          <Button
            size="sm"
            type="submit"
            form={SIGNATURE_FORM_ID}
            disabled={submit.isPending || !valid}
          >
            Attach signature
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}

/** Trusts a robodr-commission trust root for the workspace's revocation lists. */
export function AddTrustRootDialog({
  workspaceId,
  open,
  onOpenChange,
}: FleetWorkspaceDialogProps) {
  const fieldId = useId()
  const add = useAddFleetTrustRoot(workspaceId)
  const [publicKey, setPublicKey] = useState("")
  const [label, setLabel] = useState("")

  async function handleSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    try {
      const root = await add.mutateAsync({
        public_key: publicKey.trim(),
        label: label.trim() || null,
      })
      toast({ title: "Trust root added", description: root.key_id })
      setPublicKey("")
      setLabel("")
      onOpenChange(false)
    } catch (err) {
      failed("Failed to add trust root", err)
    }
  }

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent size="md">
        <DialogHeader>
          <DialogTitle>Add trust root</DialogTitle>
          <DialogDescription>
            Revocation lists are published only when one of these trust roots
            signed them.
          </DialogDescription>
        </DialogHeader>
        <DialogBody>
          <form
            id={TRUST_ROOT_FORM_ID}
            className="space-y-4"
            onSubmit={handleSubmit}
          >
            <div className="space-y-2">
              <Label htmlFor={`${fieldId}-key`}>Public key</Label>
              <Textarea
                id={`${fieldId}-key`}
                value={publicKey}
                onChange={(event) => setPublicKey(event.target.value)}
                className="min-h-[100px] font-mono text-xs"
                placeholder="robodr-blackbox-key/v2 .pub file or 64 hex digits"
                required
              />
            </div>
            <div className="space-y-2">
              <Label htmlFor={`${fieldId}-label`}>Label (optional)</Label>
              <Input
                id={`${fieldId}-label`}
                value={label}
                onChange={(event) => setLabel(event.target.value)}
                maxLength={128}
              />
            </div>
          </form>
        </DialogBody>
        <DialogFooter>
          <Button
            size="sm"
            type="submit"
            form={TRUST_ROOT_FORM_ID}
            disabled={add.isPending || !publicKey.trim()}
          >
            Add
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}
