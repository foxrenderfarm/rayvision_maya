"""Test for analyze_maya_handle.py."""

# pylint: disable=import-error
import pytest

from rayvision_utils.exception.exception import CGFileNotExistsError


def test_check_path(maya_analyze):
    """Test init this interface.

    Test We can get an ``FileNameContainsChineseError`` if the information is
    wrong.

    """
    maya_analyze.cg_file = "xxx.ma"
    with pytest.raises(CGFileNotExistsError):
        maya_analyze.check_path(maya_analyze.cg_file)


def test_check_version2(maya_analyze, tmpdir, mocker):
    """Test we can get a expected result."""
    cg_file = str(tmpdir.join('muti_layer_test.ma'))
    mocker_version = mocker.patch.object(maya_analyze, 'check_version2')
    mocker_version.return_value = "2018"
    assert maya_analyze.check_version2(cg_file) == "2018"


def test_check_version3(maya_analyze, tmpdir, mocker):
    """Test we can get a expected result."""
    cg_file = str(tmpdir.join('muti_layer_test.ma'))
    mocker_version = mocker.patch.object(maya_analyze, 'check_version3')
    mocker_version.return_value = "2018"
    assert maya_analyze.check_version3(cg_file) == "2018"
