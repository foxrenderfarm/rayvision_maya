#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os
import sys
import json
import codecs

from Analyze import analyze_maya

try:
    channel
except:
    is_channel_exists = False
else:
    is_channel_exists = True
    
if is_channel_exists and channel == 'api':
    # api + linux
    # params in cmd: channel, options_json
    # params in options_json: cg_file, task_id, task_json, asset_json, tips_json, cg_project, cg_plugins, cg_version, channel
    with codecs.open(options_json, 'r', 'utf-8') as f_options_json:
        options = json.load(f_options_json)
else:
    #linux
    options = {}
    options["cg_file"] = cg_file
    options["cg_project"] = cg_project
    options["task_json"] = task_json
    if os.path.exists(options["task_json"]):
        options["asset_json"] = os.path.join(os.path.dirname(options["task_json"]),"asset.json").replace("\\","/")
        options["tips_json"] = os.path.join(os.path.dirname(options["task_json"]),"tips.json").replace("\\","/")
        options["system_json"] = os.path.join(os.path.dirname(options["task_json"]),"system.json").replace("\\","/")
        with codecs.open(options["task_json"],'r', 'utf-8') as f_task_json:
            task_json_dict = json.load(f_task_json)
        options["cg_version"] = task_json_dict['software_config']['cg_version']
        options["cg_plugins"] = task_json_dict['software_config']['plugins']
        with codecs.open(options["system_json"], 'r', 'utf-8') as f_system_json:
            system_json_dict = json.load(f_system_json)
        options["platform"] = system_json_dict['system_info']['common']['platform']
        options["channel"] = "web"
    else:
        print("task.json is not exists")
        sys.exit(555)
analyze_maya(options)
