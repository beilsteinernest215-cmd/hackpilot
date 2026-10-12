# HackPilot core module
import pytest
from advance_hackpilot import EnterpriseHackPilot, EnterpriseWebDashboard

def test_enterprise_web_dashboard_initialization():
    app_instance = EnterpriseHackPilot()
    dashboard = EnterpriseWebDashboard(app_instance)
    assert dashboard.hackpilot == app_instance
    assert dashboard.app is not None
