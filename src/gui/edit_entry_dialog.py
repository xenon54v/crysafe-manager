from __future__ import annotations

from src.gui.entry_dialog import EntryDialog


class EditEntryDialog(EntryDialog):
    def __init__(
        self,
        master=None,
        entry: dict | None = None,
        generator=None,
        username_suggester=None,
    ) -> None:
        super().__init__(
            master,
            entry=entry,
            generator=generator,
            username_suggester=username_suggester,
            window_title="Edit Entry",
            heading="Edit Vault Entry",
        )
