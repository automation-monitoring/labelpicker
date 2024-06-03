#!/usr/bin/env python3
# -*- encoding: utf-8; py-indent-offset: 4 -*-

# SPDX-FileCopyrightText: © 2023 PL Automation Monitoring GmbH <pl@automation-monitoring.com>
# SPDX-License-Identifier: GPL-3.0-or-later
# This file is part of the Checkmk Labelpicker project (https://labelpicker.mk)

# Thanks to:
# LHM (Landeshauptstadt Muenchen): This Datasource Plugin was developed in cooperation with the "Eigenbetrieb it@M" of the City of Munich.


from labelpicker.labelpicker_base import Strategy
import re
import os
import ast

# from cmk.gui.plugins.views import builtin_inventory_plugins


class lpds_hwswtree(Strategy):
    """HWSWTree strategy"""

    def _translate_inv_tree(self, invtree):
        """Set values in invtree list to lowercase and map values if necessary"""
        invtree_translated = []
        inv_mapping = {
            "Operating System": "os",
            "Interfaces": "total_interfaces",
            "Ports": "total_ethernet_ports",
            "Default": "0.0.0.0/0",
            "Model Name": "model",
        }
        # TODO: Use builtin_inventory_plugins.inventory_displayhints for mapping
        # for item, data in builtin_inventory_plugins.inventory_displayhints.items():
        #    if "title" in data and type(data["title"]) == str:
        #        pass

        for item in invtree:
            if item in inv_mapping:
                item = inv_mapping[item]
            item = item.lower()
            invtree_translated.append(item)
        return invtree_translated

    def source_algorithm(self, **kwargs) -> dict:
        """Parse Hardware/Software inventory data"""
        inventory_dir = kwargs.get("inventory_dir", None)
        if not inventory_dir:
            inventory_dir = os.environ["HOME"] + "/var/check_mk/inventory"
        debug = False
        parsed = {}
        if debug:
            print(
                f"DEBUG: Parsing Hardware/Software inventory data from {inventory_dir}"
            )

        # iterate over all files in inventory_dir and evaluate them
        for host in os.listdir(inventory_dir):
            if not re.match("(^\.|.*\.gz$)", host):
                if debug:
                    print(f"DEBUG: Parsing {host}")
                with open(f"{inventory_dir}/{host}", "r") as file:
                    content = file.read()
                    try:
                        parsed[host] = ast.literal_eval(content)
                    except SyntaxError as e:
                        print(f"Syntax error in file {host}: {e}")
                    except ValueError as e:
                        print(f"Value error in file {host}: {e}")
        return parsed

    def _inspect_inv_dict(self, data, inv_tree, index=0):
        """Try to get value from data by inv_tree
        Search for keys Nodes, Attributes, Table
        If behind this key is NOT an empty dict try to read Attributes or Table values
        Else: try to use the inv_tree key to dig deeper via recursion.
        """
        row_mapping = {
            "packages": ("name", "version"),
            "routes": ("target", "gateway"),
            "interfaces": ("index", "speed"),
        }

        deep_inv_tree = len(inv_tree) - 1
        self.label_content = None
        cmk_inv_objects = ["Attributes", "Nodes", "Table"]
        for obj in cmk_inv_objects:
            # If Attributes, Nodes or Table is not in data continue it seems to be a structure of an old cmk version
            # Currently no parser inplemented for this, so skip it
            if not obj in data:
                continue
            if not data[obj] == {}:
                if obj == "Attributes" and index == deep_inv_tree:
                    if "Pairs" in data[obj]:
                        self.label_content = str(data[obj]["Pairs"][inv_tree[index]])
                elif obj == "Table":
                    if "Rows" in data[obj]:
                        for id, rmap in row_mapping.items():
                            if id == inv_tree[index - 1]:
                                for row in data[obj]["Rows"]:
                                    # Convert both the pattern and the target text to strings
                                    pattern = str(inv_tree[index])
                                    target_text = str(row[rmap[0]])

                                    # Now use re.search() to match the pattern anywhere in the target_text
                                    if re.search(pattern, target_text):
                                        self.label_content = row[rmap[1]]
                                        break
                                    # if re.search(inv_tree[index], row[rmap[0]]):
                                    # if row[rmap[0]] == inv_tree[index]:
                                    #    self.label_content = row[rmap[1]]
                                    #    break
                else:
                    # try to dig deeper
                    try:
                        self._inspect_inv_dict(
                            data[obj][inv_tree[index]], inv_tree, index + 1
                        )
                    except KeyError:
                        pass

    def process_algorithm(self, source_data, **kwargs) -> dict:
        """Process source data and return dict
        with host as key and labels as value"""
        collected_labels = {}
        mapping = kwargs.get("mapping", None)
        if not mapping:
            print("No mapping config found")
            return {}

        filter_blacklist = []
        for host, data in source_data.items():
            # print("Processing host: {}".format(host))
            for definition in mapping:
                inv_tree = self._translate_inv_tree(definition["tree"])
                self._inspect_inv_dict(data, inv_tree)
                if self.label_content:
                    # update collected_labels with host and label
                    if host not in collected_labels:
                        collected_labels[host] = {}
                    # set label key depending on label_prefix
                    if kwargs.get("label_prefix", None):
                        k = "{}/{}".format(
                            kwargs.get("label_prefix"), definition["labelname"]
                        )
                    else:
                        k = definition["labelname"]
                    regex_value_filter = definition.get("regex_value_filter", None)
                    # Todo: Should be implemented in labelpicker_base.py
                    # if regex_value_filter is defined, check if label_content matches regex and define variable v. If not skip the complete label
                    if regex_value_filter:
                        if not re.search(regex_value_filter, self.label_content):
                            continue

                    v = self.label_content
                    # try to apply matchgroup filter if defined
                    match_group_filters = definition.get("match_group_filters", None)
                    if match_group_filters:
                        for filter in match_group_filters:
                            if type(filter) is str:
                                # if filter is a string, switch to simple match -> first group
                                regex = filter
                                re_modified = r"\1"
                            elif type(filter) is list:
                                # if filter is a list, use first element as regex and second element as modified regex
                                regex = filter[0]
                                re_modified = filter[1]

                            if filter not in filter_blacklist:
                                try:
                                    match = re.search(regex, v)
                                    if match:
                                        # substitute match groups in re_modified string
                                        v = re.sub(
                                            r"\\(\d+)",
                                            lambda m: match.group(int(m.group(1))),
                                            re_modified,
                                        )
                                        break
                                except Exception as e:
                                    filter_blacklist.append(filter)
                                    print(
                                        f"ERROR: Could not apply match_group_filters to {k}. Exception: {e}"
                                    )
                    collected_labels[host].update({k: v})

                    # print(f"{host} -> {definition['labelname']} -> {v}")
        return collected_labels
