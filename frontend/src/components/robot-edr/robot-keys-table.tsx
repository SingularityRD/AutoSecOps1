"use client"

import { KeyRoundIcon } from "lucide-react"
import { useState } from "react"
import type { RobotKeyRead } from "@/client"
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
} from "@/components/ui/alert-dialog"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table"
import { toast } from "@/components/ui/use-toast"
import { useRevokeRobotKey } from "@/hooks/use-robot-edr"
import { getApiErrorDetail } from "@/lib/errors"
import { type RobotKeyStatus, robotKeyStatus } from "@/lib/robodr"

const STATUS_LABELS: Record<RobotKeyStatus, string> = {
  active: "Active",
  revoked: "Revoked",
  expired: "Expired",
}

/** Small status pill for a key or a robot's key summary. */
export function KeyStatusBadge({ status }: { status: RobotKeyStatus }) {
  return (
    <Badge
      variant="outline"
      className={
        status === "active"
          ? "border-emerald-500/50 text-emerald-700 dark:text-emerald-300"
          : "text-muted-foreground"
      }
    >
      {STATUS_LABELS[status]}
    </Badge>
  )
}

function shortHex(hex: string): string {
  return hex.length > 20 ? `${hex.slice(0, 8)}…${hex.slice(-8)}` : hex
}

/** Props for {@link RobotKeysTable}. */
export interface RobotKeysTableProps {
  workspaceId: string
  keys: readonly RobotKeyRead[]
  /** The user holds `robot:update`. */
  canUpdate: boolean
}

/**
 * Table of registered keys with a revoke action that asks for confirmation
 * before calling the API.
 */
export function RobotKeysTable({
  workspaceId,
  keys,
  canUpdate,
}: RobotKeysTableProps) {
  const revokeKey = useRevokeRobotKey(workspaceId)
  const [revokeTarget, setRevokeTarget] = useState<RobotKeyRead | null>(null)

  if (keys.length === 0) {
    return (
      <div className="flex items-center gap-2 rounded-md border border-dashed px-4 py-6 text-xs text-muted-foreground">
        <KeyRoundIcon className="size-4" aria-hidden />
        No keys registered yet.
      </div>
    )
  }

  return (
    <>
      <div className="rounded-md border">
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead>Key id</TableHead>
              <TableHead>Role</TableHead>
              <TableHead>Public key</TableHead>
              <TableHead>Options</TableHead>
              <TableHead>Status</TableHead>
              <TableHead>
                <span className="sr-only">Actions</span>
              </TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {keys.map((key) => {
              const status = robotKeyStatus(key)
              const options = [
                key.site ? `site ${key.site}` : null,
                key.vouches_origin ? "vouches origin" : null,
              ].filter((option) => option !== null)
              return (
                <TableRow key={key.id}>
                  <TableCell className="font-mono text-xs">
                    {key.key_id}
                  </TableCell>
                  <TableCell className="text-xs">{key.role}</TableCell>
                  <TableCell
                    className="font-mono text-xs text-muted-foreground"
                    title={key.public_key}
                  >
                    {shortHex(key.public_key)}
                  </TableCell>
                  <TableCell className="text-xs text-muted-foreground">
                    {options.length > 0 ? options.join(", ") : "None"}
                  </TableCell>
                  <TableCell>
                    <KeyStatusBadge status={status} />
                  </TableCell>
                  <TableCell className="text-right">
                    {canUpdate && status !== "revoked" ? (
                      <Button
                        variant="ghost"
                        size="sm"
                        className="h-7 text-destructive"
                        onClick={() => setRevokeTarget(key)}
                        aria-label={`Revoke key ${key.key_id}`}
                      >
                        Revoke
                      </Button>
                    ) : null}
                  </TableCell>
                </TableRow>
              )
            })}
          </TableBody>
        </Table>
      </div>

      <AlertDialog
        open={revokeTarget !== null}
        onOpenChange={(open) => !open && setRevokeTarget(null)}
      >
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>
              Revoke key {revokeTarget?.key_id}?
            </AlertDialogTitle>
            <AlertDialogDescription>
              The key stops authenticating batches and findings at once. This
              cannot be undone; register a new key to restore ingest.
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>Cancel</AlertDialogCancel>
            <AlertDialogAction
              variant="destructive"
              disabled={revokeKey.isPending}
              onClick={async () => {
                if (!revokeTarget) return
                try {
                  await revokeKey.mutateAsync(revokeTarget.id)
                  toast({
                    title: "Key revoked",
                    description: revokeTarget.key_id,
                  })
                } catch (err) {
                  toast({
                    title: "Failed to revoke key",
                    description: getApiErrorDetail(err) ?? undefined,
                    variant: "destructive",
                  })
                } finally {
                  setRevokeTarget(null)
                }
              }}
            >
              Revoke key
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </>
  )
}
