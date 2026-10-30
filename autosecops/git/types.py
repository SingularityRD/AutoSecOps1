from dataclasses import dataclass


@dataclass(frozen=True)
class GitUrl:
    """Immutable Git URL representation."""

    host: str
    org: str
    repo: str
    user: str = "git"
    ref: str | None = None

    def to_url(self) -> str:
        """Convert GitUrl to string representation."""
        base = self.remote_url()
        return f"{base}@{self.ref}" if self.ref else base

    def remote_url(self) -> str:
        """Return the cloneable ``git+ssh`` URL, without the ``@ref`` suffix.

        The ``@ref`` suffix is AutoSecOps' branch or commit selector, not part
        of the remote path, so Git commands must never receive it.
        """
        return f"git+ssh://{self.user}@{self.host}/{self.org}/{self.repo}.git"
