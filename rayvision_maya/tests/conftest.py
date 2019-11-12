"""The plugin of the pytest.

The pytest plugin hooks do not need to be imported into any test code, it will
load automatically when running pytest.

References:
    https://docs.pytest.org/en/2.7.3/plugins.html

"""

# pylint: disable=import-error
import pytest
from rayvision_api.task.handle import RayvisionTask


@pytest.fixture()
def user_info():
    """Get user info."""
    return {
        "domain": "task.renderbus.com",
        "platform": "2",
        "access_id": "df6d1d6s3dc56ds6",
        "access_key": "fa5sd565as2fd65",
        "local_os": 'windows',
        "workspace": "c:/workspace",
        "render_software": "Maya",
        "software_version": "2018",
        "project_name": "Project1",
        "plugin_config": {
            "mtoa": "3.1.2.1"
        }
    }


@pytest.fixture()
def cg_file_m(tmpdir):
    """Get render cg file."""
    return {
        'cg_file': str(tmpdir.join('muti_layer_test.ma'))
    }


@pytest.fixture()
def task(user_info, cg_file_m, mocker):
    """Create an RayvisionTask object."""
    mocker_task_id = mocker.patch.object(RayvisionTask, 'get_task_id')
    mocker_task_id.return_value = '1234567'
    mocker_user_id = mocker.patch.object(RayvisionTask, 'get_user_id')
    mocker_user_id.return_value = '10000012'
    mocker_user_id = mocker.patch.object(RayvisionTask,
                                         'check_and_add_project_name')
    mocker_user_id.return_value = '147258'
    return RayvisionTask(cg_file=cg_file_m['cg_file'], **user_info)


@pytest.fixture()
def maya(cg_file_m, task):
    """Create an Maya object."""
    from rayvision_maya.analyze_maya_handle import Maya
    return Maya(str(cg_file_m['cg_file']), task, 2000, '')
