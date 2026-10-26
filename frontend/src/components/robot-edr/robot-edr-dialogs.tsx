"use client"

import { type FormEvent, useId, useState } from "react"
import type { RobotKeyCreate, RobotKeyRead, RobotKeyRole } from "@/client"
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
import { Switch } from "@/components/ui/switch"
import { toast } from "@/components/ui/use-toast"
import { useCreateRobot, useCreateRobotKey } from "@/hooks/use-robot-edr"
import { getApiErrorDetail } from "@/lib/errors"
import { PUBLIC_KEY_HEX_PATTERN, ROBOT_ID_PATTERN } from "@/lib/robodr"

const REGISTER_ROBOT_FORM_ID = "register-robot-form"
const ADD_KEY_FORM_ID = "add-robot-key-form"

function optional(value: string): string | null {
  const trimmed = value.trim()
  return trimmed ? trimmed : null
}

function FieldError({ id, message }: { id: string; message: string | null }) {
  if (!message) {
    return null
  }
  return (
    <p id={id} role="alert" className="text-xs text-destructive">
      {message}
    </p>
  )
}

/** Props for {@link RegisterRobotDialog}. */
export interface RegisterRobotDialogProps {
  workspaceId: string
  open: boolean
  onOpenChange: (open: boolean) => void
}

/** Dialog that registers a robot by its RoboDR robot id. */
export function RegisterRobotDialog({
  workspaceId,
  open,
  onOpenChange,
}: RegisterRobotDialogProps) {
  const fieldId = useId()
  const createRobot = useCreateRobot(workspaceId)
  const [robotId, setRobotId] = useState("")
  const [site, setSite] = useState("")
  const [model, setModel] = useState("")
  const [morphology, setMorphology] = useState("")
  const [requireSignature, setRequireSignature] = useState(false)
  const [robotIdError, setRobotIdError] = useState<string | null>(null)

  function reset() {
    setRobotId("")
    setSite("")
    setModel("")
    setMorphology("")
    setRequireSignature(false)
    setRobotIdError(null)
  }

  async function handleSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    const id = robotId.trim()
    if (!ROBOT_ID_PATTERN.test(id)) {
      setRobotIdError(
        "Use 1-64 letters, digits, dots, underscores or hyphens, as in the robot's RoboDR config."
      )
      return
    }
    setRobotIdError(null)
    try {
      await createRobot.mutateAsync({
        robot_id: id,
        site: optional(site),
        model: optional(model),
        morphology: optional(morphology),
        require_finding_signature: requireSignature,
      })
      toast({ title: "Robot registered", description: id })
      reset()
      onOpenChange(false)
    } catch (err) {
      toast({
        title: "Failed to register robot",
        description: getApiErrorDetail(err) ?? undefined,
        variant: "destructive",
      })
    }
  }

  return (
    <Dialog
      open={open}
      onOpenChange={(next) => {
        if (!next) reset()
        onOpenChange(next)
      }}
    >
      <DialogContent size="md">
        <DialogHeader>
          <DialogTitle>Register robot</DialogTitle>
          <DialogDescription>
            Findings from a robot are accepted only after it is registered.
          </DialogDescription>
        </DialogHeader>
        <DialogBody>
          <form
            id={REGISTER_ROBOT_FORM_ID}
            className="space-y-4"
            onSubmit={handleSubmit}
            noValidate
          >
            <div className="space-y-1.5">
              <Label htmlFor={`${fieldId}-robot-id`}>Robot id</Label>
              <Input
                id={`${fieldId}-robot-id`}
                value={robotId}
                onChange={(event) => setRobotId(event.target.value)}
                placeholder="ugv-001"
                autoComplete="off"
                aria-invalid={robotIdError !== null}
                aria-describedby={
                  robotIdError ? `${fieldId}-robot-id-error` : undefined
                }
                required
              />
              <FieldError
                id={`${fieldId}-robot-id-error`}
                message={robotIdError}
              />
            </div>
            <div className="space-y-1.5">
              <Label htmlFor={`${fieldId}-site`}>Site</Label>
              <Input
                id={`${fieldId}-site`}
                value={site}
                onChange={(event) => setSite(event.target.value)}
                placeholder="range-north"
                autoComplete="off"
              />
            </div>
            <div className="grid grid-cols-2 gap-3">
              <div className="space-y-1.5">
                <Label htmlFor={`${fieldId}-model`}>Model</Label>
                <Input
                  id={`${fieldId}-model`}
                  value={model}
                  onChange={(event) => setModel(event.target.value)}
                  autoComplete="off"
                />
              </div>
              <div className="space-y-1.5">
                <Label htmlFor={`${fieldId}-morphology`}>Morphology</Label>
                <Input
                  id={`${fieldId}-morphology`}
                  value={morphology}
                  onChange={(event) => setMorphology(event.target.value)}
                  placeholder="wheeled"
                  autoComplete="off"
                />
              </div>
            </div>
            <div className="flex items-start justify-between gap-4">
              <div className="space-y-0.5">
                <Label htmlFor={`${fieldId}-require-signature`}>
                  Require finding signatures
                </Label>
                <p className="text-xs text-muted-foreground">
                  Reject findings for this robot that carry no per-finding
                  signature.
                </p>
              </div>
              <Switch
                id={`${fieldId}-require-signature`}
                checked={requireSignature}
                onCheckedChange={setRequireSignature}
              />
            </div>
          </form>
        </DialogBody>
        <DialogFooter>
          <Button
            size="sm"
            type="submit"
            form={REGISTER_ROBOT_FORM_ID}
            disabled={createRobot.isPending}
          >
            Register
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}

/** Props for {@link AddRobotKeyDialog}. */
export interface AddRobotKeyDialogProps {
  workspaceId: string
  open: boolean
  onOpenChange: (open: boolean) => void
  /**
   * RoboDR robot id to bind `uplink` and `finding` keys to. Without it only
   * workspace-wide `relay` keys can be added.
   */
  robodrRobotId?: string | null
  /** Called with the registered key. */
  onCreated?: (key: RobotKeyRead) => void
}

const ROLE_DESCRIPTIONS: Record<RobotKeyRole, string> = {
  uplink: "Signs batches with findings of this robot only.",
  relay:
    "Signs batches for any registered robot in the workspace, such as a sensor box or the diode importer.",
  finding: "Verifies the optional per-finding signature. Never signs a batch.",
  blackbox:
    "Verifies black-box records and evidence bundles. Registered at fleet enrollment; never signs a batch.",
}

/**
 * Dialog that registers an Ed25519 public key from its 64-digit hex form,
 * with the key role and the relay-only site and vouches-origin options.
 */
export function AddRobotKeyDialog({
  workspaceId,
  open,
  onOpenChange,
  robodrRobotId,
  onCreated,
}: AddRobotKeyDialogProps) {
  const fieldId = useId()
  const createKey = useCreateRobotKey(workspaceId)
  const roles: RobotKeyRole[] = robodrRobotId
    ? ["uplink", "relay", "finding", "blackbox"]
    : ["relay"]
  const [role, setRole] = useState<RobotKeyRole>(roles[0])
  const [publicKey, setPublicKey] = useState("")
  const [keyId, setKeyId] = useState("")
  const [site, setSite] = useState("")
  const [vouchesOrigin, setVouchesOrigin] = useState(false)
  const [publicKeyError, setPublicKeyError] = useState<string | null>(null)

  function reset() {
    setRole(roles[0])
    setPublicKey("")
    setKeyId("")
    setSite("")
    setVouchesOrigin(false)
    setPublicKeyError(null)
  }

  async function handleSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    const hex = publicKey.trim().toLowerCase()
    if (!PUBLIC_KEY_HEX_PATTERN.test(hex)) {
      setPublicKeyError(
        "Paste the public_hex of the RoboDR .key.pub file: 64 hex digits."
      )
      return
    }
    setPublicKeyError(null)
    const requestBody: RobotKeyCreate =
      role === "relay"
        ? {
            role,
            public_key: hex,
            site: optional(site),
            vouches_origin: vouchesOrigin,
          }
        : {
            role,
            public_key: hex,
            robot_id: robodrRobotId ?? null,
            key_id: role === "finding" ? optional(keyId) : null,
          }
    try {
      const created = await createKey.mutateAsync(requestBody)
      toast({ title: "Key registered", description: created.key_id })
      onCreated?.(created)
      reset()
      onOpenChange(false)
    } catch (err) {
      toast({
        title: "Failed to register key",
        description: getApiErrorDetail(err) ?? undefined,
        variant: "destructive",
      })
    }
  }

  return (
    <Dialog
      open={open}
      onOpenChange={(next) => {
        if (!next) reset()
        onOpenChange(next)
      }}
    >
      <DialogContent size="md">
        <DialogHeader>
          <DialogTitle>Add public key</DialogTitle>
          <DialogDescription>
            Register an Ed25519 public key. Only public material is stored.
          </DialogDescription>
        </DialogHeader>
        <DialogBody>
          <form
            id={ADD_KEY_FORM_ID}
            className="space-y-4"
            onSubmit={handleSubmit}
            noValidate
          >
            <div className="space-y-1.5">
              <Label htmlFor={`${fieldId}-role`}>Role</Label>
              <Select
                value={role}
                onValueChange={(value) => setRole(value as RobotKeyRole)}
              >
                <SelectTrigger id={`${fieldId}-role`}>
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  {roles.map((candidate) => (
                    <SelectItem key={candidate} value={candidate}>
                      {candidate}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
              <p className="text-xs text-muted-foreground">
                {ROLE_DESCRIPTIONS[role]}
                {role === "relay" && robodrRobotId
                  ? " Relay keys are not bound to this robot."
                  : ""}
              </p>
            </div>
            <div className="space-y-1.5">
              <Label htmlFor={`${fieldId}-public-key`}>Public key (hex)</Label>
              <Input
                id={`${fieldId}-public-key`}
                value={publicKey}
                onChange={(event) => setPublicKey(event.target.value)}
                placeholder="64 hex digits"
                className="font-mono text-xs"
                autoComplete="off"
                spellCheck={false}
                aria-invalid={publicKeyError !== null}
                aria-describedby={
                  publicKeyError ? `${fieldId}-public-key-error` : undefined
                }
                required
              />
              <FieldError
                id={`${fieldId}-public-key-error`}
                message={publicKeyError}
              />
            </div>
            {role === "finding" ? (
              <div className="space-y-1.5">
                <Label htmlFor={`${fieldId}-key-id`}>Key id (optional)</Label>
                <Input
                  id={`${fieldId}-key-id`}
                  value={keyId}
                  onChange={(event) => setKeyId(event.target.value)}
                  placeholder="Defaults to ed25519:<16 hex>"
                  autoComplete="off"
                />
              </div>
            ) : null}
            {role === "relay" ? (
              <>
                <div className="space-y-1.5">
                  <Label htmlFor={`${fieldId}-site`}>Site (optional)</Label>
                  <Input
                    id={`${fieldId}-site`}
                    value={site}
                    onChange={(event) => setSite(event.target.value)}
                    placeholder="range-north"
                    autoComplete="off"
                  />
                  <p className="text-xs text-muted-foreground">
                    The key reports only robots registered with this site.
                  </p>
                </div>
                <div className="flex items-start justify-between gap-4">
                  <div className="space-y-0.5">
                    <Label htmlFor={`${fieldId}-vouches-origin`}>
                      Vouches origin
                    </Label>
                    <p className="text-xs text-muted-foreground">
                      Set only on the diode importer's key: its findings satisfy
                      a robot's signature requirement.
                    </p>
                  </div>
                  <Switch
                    id={`${fieldId}-vouches-origin`}
                    checked={vouchesOrigin}
                    onCheckedChange={setVouchesOrigin}
                  />
                </div>
              </>
            ) : null}
          </form>
        </DialogBody>
        <DialogFooter>
          <Button
            size="sm"
            type="submit"
            form={ADD_KEY_FORM_ID}
            disabled={createKey.isPending}
          >
            Add key
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}
