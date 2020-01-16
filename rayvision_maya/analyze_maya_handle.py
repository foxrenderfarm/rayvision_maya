# -*- coding: utf-8 -*-
"""A interface for maya."""

# Import built-in models
from __future__ import print_function
from __future__ import unicode_literals

import codecs
import json
import math
import os
import re
import sys
import traceback

from rayvision_utils import utils
from rayvision_utils.exception import tips_code
from rayvision_utils.exception.error_msg import ERROR9899_CGEXE_NOTEXIST
from rayvision_utils.exception.error_msg import VERSION_NOT_MATCH
from rayvision_utils.exception.exception import AnalyseFailError
from rayvision_utils.exception.exception import CGExeNotExistError
from rayvision_utils.exception.exception import FileNameContainsChineseError
from rayvision_utils.exception.exception import GetCGVersionError
from rayvision_utils.exception.exception import VersionNotMatchError
from rayvision_utils.json_handle import JsonHandle

VERSION = sys.version_info[0]


class Maya(JsonHandle):
    """Inherit JsonHandle.

    Mainly responsible for the processing before and after analysis.

    """

    def __init__(self, *args, **kwargs):
        """Initialize handle maya object."""
        super(Maya, self).__init__(*args, **kwargs)
        self.exe_name = "mayabatch.exe"
        self.name = "Maya"

        self.init()

    def init(self):
        """Check if the scene file name has Chinese.

        Raises:
            FileNameContainsChineseError: Scene file name has Chinese.

        """
        cg_file = self.cg_file
        if utils.check_contain_chinese(cg_file):
            self.tips.add(tips_code.CONTAIN_CHINESE, cg_file)
            self.tips.save_tips()
            raise FileNameContainsChineseError

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
                # file_infos = re.findall(
                #     br'FINF\x00+\x11?\x12?K?\r?(.+?)\x00(.+?)\x00',
                #     info, re.I)
                # for i in file_infos:
                #     if i[0] == b"product":
                #         try:
                #             result = int(i[1].split()[1])
                #         except Exception:
                #             raise GetCGVersionError

        return result

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

        return result

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
        log = self.logger
        version = self.version
        exe_path = None
        if self.local_os == 'windows':
            location = self.location_from_reg(version)
            exe_path = self.exe_path_from_location(
                os.path.join(location, "bin"), self.exe_name)
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
            self.tips.add(tips_code.CG_NOTEXISTS, self.version_str)
            self.tips.save_tips()
            raise CGExeNotExistError(ERROR9899_CGEXE_NOTEXIST.format(
                self.name))

        self.exe_path = exe_path
        log.info("exe_path: %s", self.exe_path)

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
        version = str(version)
        self.version = str(version)
        self.version_str = "{0} {1}".format(self.name, version)
        # Find the installation path with the version
        if self.custom_exe_path is not None:
            self.exe_path = self.custom_exe_path
        else:
            self.find_location()

    def valid(self):
        """Check version.

        Check whether the version of the scene file is consistent with the
        configured version.

        Raises:
            VersionNotMatchError: Version does not match.

        """
        software_config = self.task.task_info["software_config"]
        cg_version = software_config["cg_version"]
        # If you find a version of .5, consider it an integer version
        # outer int for compatibility with py2
        cg_version = str(int(math.floor(int(cg_version))))
        cg_name = software_config["cg_name"]
        self.logger.debug("cg_name= %s, cg_version= %s", cg_name, cg_version)

        if (cg_name.capitalize() != self.name.capitalize()
                and cg_version != self.version):
            self.tips.add(tips_code.CG_NOTMATCH, self.version_str)
            self.tips.save_tips()
            raise VersionNotMatchError(VERSION_NOT_MATCH)

    def analyse(self):
        """Build a cmd command to perform an analysis scenario.

        Raises:
            AnalyseFailError: Analysis scenario failed.

        """
        analyse_script_name = "Analyze"
        channel = 'api'

        options = {
            "cg_file": self.cg_file.replace("\\", "/"),
            "task_json": self.task.task_json_path.replace("\\", "/"),
            "asset_json": self.task.asset_json_path.replace("\\", "/"),
            "tips_json": self.task.tips_json_path.replace("\\", "/"),
            "cg_project": (os.path.dirname(os.path.normpath(__file__)).
                           replace("\\", "/")),
            "cg_plugins": self.task.task_info["software_config"]["plugins"],
            "cg_version": self.version,
            "user_id": self.task.user_id,
            "channel": channel
        }

        script_path = (os.path.dirname(os.path.normpath(__file__)).
                       replace("\\", "/"))
        analyze_py_path = os.path.join(script_path, 'temp.py')

        if self.local_os == 'windows':
            cmd = ('"{exe_path}" -command "python \\"options={options};'
                   'import sys;sys.path.insert(0, \'{script_path}\');'
                   'import {analyse_script_name};reload({analyse_script_name}'
                   ');{analyse_script_name}.analyze_maya(options)\\""').format(
                       exe_path=self.exe_path,
                       options=options,
                       script_path=script_path,
                       analyse_script_name=analyse_script_name)
        else:
            options_json = os.path.join(os.path.dirname(
                self.task.task_json_path), 'options.json')
            with codecs.open(options_json, 'w', 'utf-8') as f_options_json:
                json.dump(options, f_options_json, ensure_ascii=False,
                          indent=4)

            # cmd = ('\"%s\" -batch -command \"python \\\"'
            #        'options=dict(task_json=\\\\\\\"%s\\\\\\\",'
            #        'channel=\\\\\\\"%s\\\\\\\",'
            #        'client_script=\\\\\\\"%s\\\\\\\");'
            #        'import sys;sys.path.insert(0, \\\\\\\"%s\\\\\\\");'
            #        'import Analyze;reload(Analyze);'
            #        'Analyze.analyze_maya(options)\\\"\"') % (
            #            self.exe_path, self.task_json,
            #            "client", script_path, analyze_py_path)

            cmd = ('"{exe_path}" -batch -command "python \\\"channel,'
                   'options_json=\\\\\\\"{channel}\\\\\\\",'
                   '\\\\\\\"{options_json}\\\\\\\";'
                   'import sys;sys.path.insert(0,'
                   ' \\\\\\\"{script_path}\\\\\\\");'
                   'execfile(\\\\\\\"{analyze_py_path}\\\\\\\")\\\""').format(
                       exe_path=self.exe_path,
                       channel=channel,
                       options_json=options_json,
                       script_path=script_path,
                       analyze_py_path=analyze_py_path,
                       )

        self.logger.debug(cmd)
        code, _, _ = self.cmd.run(cmd, shell=True)
        if code != 0:
            self.tips.add(tips_code.UNKNOW_ERR)
            self.tips.save_tips()
            raise AnalyseFailError

        # Determine whether the analysis is successful by
        #  determining whether a json file is generated.
        status, msg = self.json_exist()
        if status is False:
            self.tips.add(tips_code.UNKNOW_ERR, msg)
            self.tips.save_tips()
            raise AnalyseFailError(msg)

    def handle_analyse_result(self):
        """Handle analyse result.

        Save the analyzed scene file information and texture information to
        the upload.json file.

        """
        upload_asset = []

        asset_json = self.asset_json
        assets = asset_json["asset"]
        for asset_dict in assets:
            path_list = asset_dict["path"]

            for path in path_list:
                resources = {}
                local = path.split("  (mtime)")[0]
                server = utils.convert_path(local)
                resources["local"] = local.replace("\\", "/")
                resources["server"] = server
                upload_asset.append(resources)

        # Add the cg file to upload.json
        upload_asset.append({
            "local": self.cg_file.replace("\\", "/"),
            "server": utils.convert_path(self.cg_file)
        })

        upload_json = dict()
        upload_json["asset"] = upload_asset

        self.upload_json = upload_json
        self.task.upload_info = upload_json

        utils.json_save(self.task.upload_json_path, upload_json)

    def run(self):
        """Perform an overall analysis process."""
        # run a custom script if exists
        # Analyze pre-custom scripts (configuration environment,
        #  specify the corresponding BAT/SH)
        # self.preAnalyseCustomScript()
        # Get scene information
        self.analyse_cg_file()
        # Basic check (whether the version of the project configuration and
        #  the version of the scenario match, etc.)
        self.valid()
        # Set tasks.task_info dump into a file
        self.dump_task_json()
        # Run CMD startup analysis (find the path of CG through configuration
        #  information, the path of CG can be customized)
        self.analyse()
        # Read the three json of the analysis result into memory
        self.load_output_json()
        # Write tasks configuration file (custom information,
        #  independent upload list), compress specific files
        # (compress files, upload path, delete path)
        self.handle_analyse_result()
        # Write cg_file and cg_id to task_info
        self.write_cg_path()

        self.logger.info("analyse end.")
