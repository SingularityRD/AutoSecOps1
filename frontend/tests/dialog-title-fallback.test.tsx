import { render, screen } from "@testing-library/react"

import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog"

function NestedTitleForm() {
  return (
    <DialogHeader>
      <DialogTitle>Invite member</DialogTitle>
    </DialogHeader>
  )
}

describe("DialogContent title fallback", () => {
  it("names the dialog after a title rendered by a child component", () => {
    render(
      <Dialog open>
        <DialogContent>
          <NestedTitleForm />
        </DialogContent>
      </Dialog>
    )

    expect(
      screen.getByRole("dialog", { name: "Invite member" })
    ).toBeInTheDocument()
    expect(screen.queryByText("Dialog")).not.toBeInTheDocument()
  })

  it("names the dialog after a direct title", () => {
    render(
      <Dialog open>
        <DialogContent>
          <DialogTitle>Create credential</DialogTitle>
        </DialogContent>
      </Dialog>
    )

    expect(
      screen.getByRole("dialog", { name: "Create credential" })
    ).toBeInTheDocument()
  })

  it("falls back to the hidden title when no title is rendered", () => {
    render(
      <Dialog open>
        <DialogContent title="Untitled panel">
          <p>Body</p>
        </DialogContent>
      </Dialog>
    )

    expect(
      screen.getByRole("dialog", { name: "Untitled panel" })
    ).toBeInTheDocument()
  })
})
