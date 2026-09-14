from src.gui.widgets.secure_table import format_modified, mask_username


def test_username_is_masked_after_first_four_characters():
    assert mask_username("developer") == "deve••••"
    assert mask_username("abc") == "abc••••"


def test_modified_date_is_human_readable():
    assert format_modified("2026-09-14T10:15:00+00:00").startswith("2026-09-14")
