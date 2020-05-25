"""The plugin of the pytest.

The pytest plugin hooks do not need to be imported into any test code, it will
load automatically when running pytest.

References:
    https://docs.pytest.org/en/2.7.3/plugins.html

"""

# pylint: disable=import-error
import pytest

from rayvision_maya.analyze_maya import AnalyzeMaya


@pytest.fixture()
def analyze_info(tmpdir):
    """Get user info."""
    cg_file = str(tmpdir.join('muti_layer_test.ma'))
    with open(cg_file, "w"):
        pass
    return {
        "cg_file": cg_file,
        "workspace": str(tmpdir),
        "software_version": "2018",
        "project_name": "Project1",
        "plugin_config": {
            "mtoa": "3.1.2.1"
        }
    }


@pytest.fixture()
def maya_analyze(analyze_info):
    """Create an Maya object."""
    return AnalyzeMaya(**analyze_info)
