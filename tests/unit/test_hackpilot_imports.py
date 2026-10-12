# HackPilot core module
"""Smoke imports for the advance_hackpilot entry point."""


def test_advance_hackpilot_core_classes_import():
    from advance_hackpilot import EnterpriseHackPilot, EnterpriseToolManager

    assert EnterpriseHackPilot is not None
    assert EnterpriseToolManager is not None


def test_advance_hackpilot_compatibility_aliases():
    from advance_hackpilot import EnterpriseHackGPT, HackGPT, HackPilot

    assert EnterpriseHackGPT is not None
    assert HackGPT is not None
    assert HackPilot is not None
