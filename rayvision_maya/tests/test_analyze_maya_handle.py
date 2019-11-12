"""Test for analyze_maya_handle.py."""

# pylint: disable=import-error
import pytest
from rayvision_utils.exception.exception import FileNameContainsChineseError
from rayvision_utils.exception.exception import VersionNotMatchError

from rayvision_maya.analyze_maya_handle import Maya


def test_init(maya, tmpdir):
    """Test init this interface.

    Test We can get an ``FileNameContainsChineseError`` if the information is
    wrong.

    """
    maya.cg_file = str(tmpdir.join("资源名不能带中文.ma"))
    with pytest.raises(FileNameContainsChineseError):
        maya.init()


def test_check_version2(maya, tmpdir, mocker):
    """Test we can get a expected result."""
    cg_file = str(tmpdir.join('muti_layer_test.ma'))
    mocker_version = mocker.patch.object(Maya, 'check_version2')
    mocker_version.return_value = "2018"
    assert maya.check_version2(cg_file) == "2018"


def test_valid(maya):
    """Test valid this interface.

    Test We can get an ``VersionNotMatchError`` if the information is wrong.

    """
    maya.name = ""
    maya.version = "2014"
    with pytest.raises(VersionNotMatchError):
        maya.valid()
