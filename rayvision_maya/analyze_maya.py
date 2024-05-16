# -*- coding: utf-8 -*-
"""A interface for maya."""

# Import built-in models
from __future__ import print_function
from __future__ import unicode_literals

import codecs
import hashlib
import json
import logging
import os
import re
import sys
import time
import traceback
from builtins import str
import threading

from rayvision_maya.constants import PACKAGE_NAME
from rayvision_log import init_logger
from rayvision_utils import constants
from rayvision_utils import utils
from rayvision_utils.cmd import Cmd
from rayvision_utils.exception import tips_code
from rayvision_utils.exception.error_msg import ERROR9899_CGEXE_NOTEXIST
from rayvision_utils.exception.exception import AnalyseFailError, CGFileNotExistsError
from rayvision_utils.exception.exception import CGExeNotExistError
from rayvision_utils.exception.exception import GetCGVersionError

VERSION = sys.version_info[0]


class AnalyzeMaya(object):
    def __init__(self, cg_file, software_version, project_name,
                 plugin_config, render_software="Maya", render_layer_type="0",
                 input_project_path=None, local_os=None, workspace=None,
                 custom_exe_path=None,
                 platform="2",
                 logger=None,
                 log_folder=None,
                 log_name=None,
                 log_level="DEBUG"
                 ):
        """Initialize and examine the analysis information.

        Args:
            cg_file (str): Scene file path.
            software_version (str): Software version.
            project_name (str): The project name.
            plugin_config (dict): Plugin information.
            render_software (str): Software name, Maya by default.
            render_layer_type (str): 0 is render layer, 1 is render setup.
            input_project_path (str): The working path of the scenario.
            local_os (str): System name, linux or windows.
            workspace (str): Analysis out of the result file storage path.
            custom_exe_path (str): Customize the exe path for the analysis.
            platform (str): Platform num.
            logger (object, optional): Custom log object.
            log_folder (str, optional): Custom log save location.
            log_name (str, optional): Custom log file name.
            log_level (string):  Set log level, example: "DEBUG","INFO","WARNING","ERROR".
        """
        self.logger = logger
        if not self.logger:
            init_logger(PACKAGE_NAME, log_folder, log_name)
            self.logger = logging.getLogger(__name__)
            self.logger.setLevel(level=log_level.upper())

        self.check_path(cg_file)
        self.cg_file = cg_file

        self.render_software = render_software
        self.input_project_path = input_project_path or ""
        self.render_layer_type = render_layer_type
        self.software_version = software_version
        self.project_name = project_name
        self.plugin_config = plugin_config

        local_os = self.check_local_os(local_os)
        self.local_os = local_os
        self.tmp_mark = str(int(time.time())) + str(self.get_current_id())
        workspace = os.path.join(self.check_workspace(workspace),
                                 self.tmp_mark)
        if not os.path.exists(workspace):
            os.makedirs(workspace)
        self.workspace = workspace

        if custom_exe_path:
            self.check_path(custom_exe_path)
        self.custom_exe_path = custom_exe_path

        self.platform = platform

        self.task_json = os.path.join(workspace, "task.json")
        self.tips_json = os.path.join(workspace, "tips.json")
        self.asset_json = os.path.join(workspace, "asset.json")
        self.upload_json = os.path.join(workspace, "upload.json")
        self.tips_info = {}
        self.task_info = {}
        self.asset_info = {}
        self.upload_info = {}

    @staticmethod
    def get_current_id():
        if isinstance(threading.current_thread(), threading._MainThread):
            return os.getpid()
        else:
            return threading.get_ident()

    @staticmethod
    def check_path(tmp_path):
        """Check if the path exists."""
        if not os.path.exists(tmp_path):
            raise CGFileNotExistsError("{} is not found".format(tmp_path))

    def add_tip(self, code, info):
        """Add error message.
        
        Args:
            code (str): error code.
            info (str or list): Error message description.

        """
        if isinstance(info, str):
            self.tips_info[code] = [info]
        elif isinstance(info, list):
            self.tips_info[code] = info
        else:
            raise Exception("info must a list or str.")

    def save_tips(self):
        """Write the error message to tips.json."""
        utils.json_save(self.tips_json, self.tips_info, ensure_ascii=False)

    @staticmethod
    def check_local_os(local_os):
        """Check the system name.

        Args:
            local_os (str): System name.

        Returns:
            str

        """
        if not local_os:
            if "win" in sys.platform.lower():
                local_os = "windows"
            else:
                local_os = "linux"
        return local_os

    def check_workspace(self, workspace):
        """Check the working environment.

        Args:
            workspace (str):  Workspace path.

        Returns:
            str: Workspace path.

        """
        if not workspace:
            if self.local_os == "windows":
                workspace = os.path.join(os.environ["USERPROFILE"], "renderfarm_sdk")
            else:
                workspace = os.path.join(os.environ["HOME"], "renderfarm_sdk")
        else:
            self.check_path(workspace)

        return workspace

    @staticmethod
    def check_version3(cg_file):
        """Check the CG version of the scene file when it is Python3.

        Args:
            cg_file (str): Scene file path.

        Returns:
            str: Make the CG version of the scene file.
                e.g.:
                    "2018".

        """
        result = None
        if cg_file.endswith(".ma"):
            infos = []
            with open(cg_file, "rb") as cg_f:
                while 1:
                    line = cg_f.readline()
                    if line.strip() and not line.startswith(b"//"):
                        infos.append(line.strip())
                    if line.startswith(b"createNode"):
                        break

            file_infos = [i for i in infos if i.startswith(b"fileInfo")]
            for i in file_infos:
                if b"product" in i:
                    r_info = re.findall(br'Maya.* (\d+\.?\d+)', i, re.I)
                    if r_info:
                        try:
                            result = int(r_info[0].split(b".")[0])
                        except Exception:
                            raise GetCGVersionError

        elif cg_file.endswith(".mb"):
            with open(cg_file, "r", errors='ignore') as cg_f:
                info = cg_f.readline()

                file_info = re.findall(
                    r'FINF.*?maya\s(\d+).*?', info, re.I)
                if file_info:
                    result = file_info[0]

        return str(result)

    @staticmethod
    def check_version2(cg_file):
        """Check the CG version of the scene file when it is Python2.

        Args:
            cg_file (str): Scene file path.

        Returns:
            str: Make the CG version of the scene file.
                e.g.:
                    "2018".

        """
        result = None
        if cg_file.endswith(".ma"):
            info = []
            with open(cg_file, "rb") as cg_f:
                while 1:
                    line = cg_f.readline()
                    if line.strip() and not line.startswith("//"):
                        info.append(line.strip())
                    if line.startswith("createNode"):
                        break

            file_info = [i for i in info if i.startswith("fileInfo")]
            for i in file_info:
                if "product" in i:
                    r_info = re.findall(r'Maya.* (\d+\.?\d+)', i, re.I)
                    if r_info:
                        try:
                            result = int(r_info[0].split(".")[0])
                        except Exception:
                            raise GetCGVersionError

        elif cg_file.endswith(".mb"):
            with open(cg_file, "rb") as cg_f:
                info = cg_f.readline()

            file_info = re.findall(
                r'FINF.*?maya\s(\d+).*?', info, re.I)
            if file_info:
                result = file_info[0]

        return str(result)

    def location_from_reg(self, version):
        """Get the path in the registry of the local CG.

        When the system environment is Windows or linux, get the path where the
        local Maya startup file is located in the registry.

        Args:
            version (str): Maya version.
                e.g.:
                    "2018".

        Returns:
            str: The path where Maya's startup files are located.
                e.g.:
                    "D:/Maya/Maya2018/".

        """
        temp = 2
        try:
            import _winreg
        except ImportError:
            import winreg as _winreg
            temp = 3

        versions = (version, "{0}.5".format(version))
        location = None
        for ver in versions:
            string = r'SOFTWARE\Autodesk\Maya\{0}\Setup\InstallPath'.format(
                ver)
            self.logger.debug(string)
            try:
                if temp == 2:
                    handle = _winreg.OpenKey(_winreg.HKEY_LOCAL_MACHINE,
                                             string)
                else:
                    handle = _winreg.OpenKey(_winreg.HKEY_LOCAL_MACHINE,
                                             string, 0,
                                             (_winreg.KEY_WOW64_64KEY
                                              + _winreg.KEY_READ))
                location, _type = _winreg.QueryValueEx(
                    handle, "MAYA_INSTALL_LOCATION")
                self.logger.debug('localtion: %s, type: %s', location, _type)
                break
            except WindowsError:
                self.logger.debug(traceback.format_exc())

        return location

    def find_location(self):
        """Get the path where the local Maya startup file is located.

        Raises:
            CGExeNotExistError: The path to the startup file does not exist.

        """
        version = self.software_version
        exe_path = None
        if self.local_os == 'windows':
            location = self.location_from_reg(version)
            tmp_exe_path = os.path.join(location, "bin", "mayabatch.exe")
            if os.path.exists(tmp_exe_path):
                exe_path = tmp_exe_path
        else:
            versions = (version, "{0}.5".format(version),
                        "{0}-x64".format(version))
            for ver in versions:
                exe_path = r'/usr/autodesk/maya{0}/bin/maya'.format(ver)
                if not os.path.exists(exe_path):
                    exe_path = None
                else:
                    break

        if exe_path is None:
            self.add_tip(tips_code.CG_NOTEXISTS, "{0} {1}".format(
                self.render_software, version))
            self.save_tips()
            raise CGExeNotExistError(ERROR9899_CGEXE_NOTEXIST.format(
                self.render_software))

        self.logger.info("exe_path: %s", exe_path)
        return exe_path

    def analyse_cg_file(self):
        """Analyse cg file.

        Analyze the scene file to get the path to the startup file of the CG
        software.

        """
        # Find the version from the cg file
        if VERSION == 3:
            version = self.check_version3(self.cg_file)
        else:
            version = self.check_version2(self.cg_file)

        if int(float(version)) != int(float(self.software_version)):
            self.add_tip(tips_code.CG_NOTMATCH, "{0} {1}".format(
                self.render_software, self.software_version))
            self.save_tips()

        # Find the installation path with the version
        if self.custom_exe_path is not None:
            exe_path = self.custom_exe_path
        else:
            exe_path = self.find_location()

        return exe_path

    def write_task_json(self):
        """The initialization task.json."""
        constants.TASK_INFO["task_info"]["input_cg_file"] = self.cg_file.replace("\\", "/")
        constants.TASK_INFO["task_info"]["input_project_path"] = self.input_project_path.replace("\\", "/")
        constants.TASK_INFO["task_info"]["render_layer_type"] = self.render_layer_type
        constants.TASK_INFO["task_info"]["project_name"] = self.project_name
        constants.TASK_INFO["task_info"]["cg_id"] = constants.CG_SETTING.get(self.render_software.capitalize())
        constants.TASK_INFO["task_info"]["os_name"] = "1" if self.local_os == "windows" else "0"
        constants.TASK_INFO["task_info"]["platform"] = self.platform
        constants.TASK_INFO["software_config"] = {
            "plugins": self.plugin_config,
            "cg_version": self.software_version,
            "cg_name": self.render_software
        }
        utils.json_save(self.task_json, constants.TASK_INFO)

    def check_result(self):
        """Check that the analysis results file exists."""
        for json_path in [self.task_json, self.asset_json,
                          self.tips_json]:
            if not os.path.exists(json_path):
                msg = "Json file is not generated: {0}".format(json_path)
                return False, msg
        return True, None

    def get_file_md5(self, file_path):
        """Generate the md5 values for the scenario."""
        hash_md5 = hashlib.md5()
        if os.path.exists(file_path):
            with open(file_path, 'rb') as file_path_f:
                while True:
                    data_flow = file_path_f.read(8096)
                    if not data_flow:
                        break
                    hash_md5.update(data_flow)
        return hash_md5.hexdigest()

    def write_upload_json(self):
        """Generate the upload.json."""
        assets = self.asset_info["asset"]
        upload_asset = []

        self.upload_info["scene"] = [
            {
                "local": self.cg_file.replace("\\", "/"),
                "server": utils.convert_path(self.cg_file),
                "hash": self.get_file_md5(self.cg_file)
            }
        ]

        for path in assets:
            resources = {}
            local = path.split("  (mtime")[0]
            server = utils.convert_path(local)
            resources["local"] = local.replace("\\", "/")
            resources["server"] = server
            upload_asset.append(resources)

        # Add the cg file to upload.json
        upload_asset.append({
            "local": self.cg_file.replace("\\", "/"),
            "server": utils.convert_path(self.cg_file)
        })

        self.upload_info["asset"] = upload_asset

        utils.json_save(self.upload_json, self.upload_info)

    def analyse(self, no_upload=False, exe_path=""):
        """Build a cmd command to perform an analysis scenario.

        Args:
            no_upload (bool): Do you not generate an upload,json file.

        Raises:
            AnalyseFailError: Analysis scenario failed.

        """
        if not os.path.exists(exe_path):
            exe_path = self.analyse_cg_file()
        self.write_task_json()
        analyse_script_name = "Analyze"
        channel = 'api'

        options = {
            "cg_file": self.cg_file.replace("\\", "/"),
            "task_json": self.task_json.replace("\\", "/"),
            "asset_json": self.asset_json.replace("\\", "/"),
            "tips_json": self.tips_json.replace("\\", "/"),
            "cg_project": (os.path.dirname(os.path.normpath(__file__)).
                           replace("\\", "/")),
            "cg_plugins": self.plugin_config,
            "cg_version": self.software_version,
            "user_id": "0",
            "channel": "api",
        }

        script_path = (os.path.dirname(os.path.normpath(__file__)).
                       replace("\\", "/"))
        analyze_py_path = os.path.join(script_path, 'temp.py')

        if self.local_os == 'windows':
            cmd = ('"{exe_path}" -command "python \\"options={options};'
                   'import sys, imp;sys.path.insert(0, \'{script_path}\');'
                   'import {analyse_script_name};imp.reload({analyse_script_name}'
                   ');{analyse_script_name}.analyze_maya(options)\\""').format(
                exe_path=exe_path,
                options=options,
                script_path=script_path,
                analyse_script_name=analyse_script_name)
        else:
            options_json = os.path.join(os.path.dirname(
                self.task_json), 'options.json')
            with codecs.open(options_json, 'w', 'utf-8') as f_options_json:
                json.dump(options, f_options_json, ensure_ascii=False,
                          indent=4)
            cmd = ('"{exe_path}" -batch -command "python \\\"channel,'
                   'options_json=\\\\\\\"{channel}\\\\\\\",'
                   '\\\\\\\"{options_json}\\\\\\\";'
                   'import sys;sys.path.insert(0,'
                   ' \\\\\\\"{script_path}\\\\\\\");'
                   'execfile(\\\\\\\"{analyze_py_path}\\\\\\\")\\\""').format(
                exe_path=exe_path,
                channel=channel,
                options_json=options_json,
                script_path=script_path,
                analyze_py_path=analyze_py_path,
            )

        self.logger.debug(cmd)
        code, _, _ = Cmd.run(cmd, shell=True)
        if code != 0:
            self.add_tip(tips_code.UNKNOW_ERR, "")
            self.save_tips()
            raise AnalyseFailError

        # Determine whether the analysis is successful by
        #  determining whether a json file is generated.
        status, msg = self.check_result()
        if status is False:
            self.add_tip(tips_code.UNKNOW_ERR, msg)
            self.save_tips()
            raise AnalyseFailError(msg)

        self.tips_info = utils.json_load(self.tips_json)
        self.asset_info = utils.json_load(self.asset_json)
        self.task_info = utils.json_load(self.task_json)
        if not no_upload:
            self.write_upload_json()
