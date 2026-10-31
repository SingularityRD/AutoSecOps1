/**
 * Cookie that remembers the last workspace a user viewed, so the app can
 * reopen it on the next visit. Error boundaries clear it so a workspace that
 * failed to render is not revived on the next page load.
 */
export const LAST_VIEWED_WORKSPACE_COOKIE =
  "__autosecops:workspaces:last-viewed"
