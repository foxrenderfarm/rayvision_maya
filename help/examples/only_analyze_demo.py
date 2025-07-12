# -*- coding: utf-8 -*-

from rayvision_maya.analyze_maya import AnalyzeMaya

analyze_info = {
    "cg_file": r"D:\houdini\CG file\muti_layer_test.ma",
    "workspace": "c:/workspace",
    "software_version": "2018",
    "project_name": "Project1",
    "plugin_config": {
        "mtoa": "3.1.2.1"
    }
}

AnalyzeMaya(**analyze_info).analyse()
