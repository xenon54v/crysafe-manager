from scripts.project_checks import find_import_cycles, find_unresolved_comments


def test_source_tree_has_no_circular_imports():
    assert find_import_cycles() == []


def test_source_tree_has_no_unresolved_todo_or_fixme_comments():
    assert find_unresolved_comments() == []
