from __future__ import annotations

from src.gui.entry_dialog import EntryDialog, EntryResult


class AddEntryDialog(EntryDialog):
    def __init__(self, master=None, generator=None, username_suggester=None) -> None:
        super().__init__(
            master,
            generator=generator,
            username_suggester=username_suggester,
            window_title="Add Entry",
            heading="Add Vault Entry",
        )


__all__ = ["AddEntryDialog", "EntryResult"]
