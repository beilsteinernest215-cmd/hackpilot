# HackPilot core module
"""advance_hackpilot optional-import helper."""

import advance_hackpilot

def test_safe_import_missing_module_returns_none():
    assert advance_hackpilot.safe_import("this_module_definitely_does_not_exist_xyz") is None

def test_safe_import_existing_module():
    assert advance_hackpilot.safe_import("json") is not None
