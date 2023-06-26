#!/usr/bin/env python3
# -*- encoding: utf-8; py-indent-offset: 4 -*-
# SPDX-FileCopyrightText: © 2023 PL Automation Monitoring GmbH <pl@automation-monitoring.com>
# SPDX-License-Identifier: GPL-3.0-or-later
# This file is part of the Checkmk Labelpicker project (https://labelpicker.mk)

# Thanks to:
# Abraxas Informatik AG: This Datasource Plugin was developed in cooperation with the "Abraxas Informatik AG".

from labelpicker.labelpicker_base import Strategy
import json
import requests

# from requests.auth import HTTPBasicAuth
from requests.packages.urllib3.exceptions import InsecureRequestWarning


import requests


class vSphereAPI:
    def __init__(self, api_url, api_user, api_pass, verify_ssl=True):
        self.api_url = api_url
        self.api_user = api_user
        self.api_pass = api_pass
        self.verify_ssl = verify_ssl
        # Disable SSL warnings if verify = false
        if not verify_ssl:
            requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
        self.sid = self.auth_vcenter()

    def auth_vcenter(self):
        url = "{}/com/vmware/cis/session".format(self.api_url)
        resp = requests.post(
            url, auth=(self.api_user, self.api_pass), verify=self.verify_ssl
        )
        if resp.status_code != 200:
            self.print_error(resp, "API authentication failed")
            return None
        return resp.json().get("value")

    def make_request(self, method, url, headers=None, data=None):
        resp = requests.request(
            method, url, headers=headers, data=data, verify=self.verify_ssl
        )
        if resp.status_code != 200:
            self.print_error(resp, "API request failed")
            return None
        return resp

    def print_error(self, response, message):
        print(f"Error! {message}: {response.status_code}")
        print("Error! API responded with Message: {}".format(response.text))

    def get_api_data(self, req_url):
        headers = {"vmware-api-session-id": self.sid}
        resp = self.make_request("GET", req_url, headers=headers)
        return resp.json() if resp else None

    def post_api_data(self, req_url, req_data):
        headers = {
            "vmware-api-session-id": self.sid,
            "content-type": "application/json",
        }
        data = json.dumps(req_data)
        resp = self.make_request("POST", req_url, headers=headers, data=data)
        return resp.json() if resp else None

    def get_all_vms(self):
        resp = self.get_api_data(f"{self.api_url}/vcenter/vm")
        return resp.get("value") if resp else None

    def get_vm_tags(self, vm_id):
        url = "{}/com/vmware/cis/tagging/tag-association?~action=list-attached-tags".format(
            self.api_url
        )
        req_data = {"object_id": {"type": "VirtualMachine", "id": vm_id}}
        resp = self.post_api_data(url, req_data)
        return resp if resp else None

    def get_tag_category(self, cat_id):
        url = "{}/com/vmware/cis/tagging/category/id:{}".format(self.api_url, cat_id)
        resp = self.get_api_data(url)
        return resp if resp else None

    def get_vsphere_tag(self, tag_id):
        url = "{}/com/vmware/cis/tagging/tag/id:{}".format(self.api_url, tag_id)
        resp = self.get_api_data(url)
        return resp if resp else None


class lpds_vsphere(Strategy):
    """vSphere strategy"""

    def source_algorithm(self, **kwargs) -> dict:
        """Return dict of source data"""
        verify_ssl = kwargs.get("verify_ssl", True)
        api_url = kwargs.get("api_url", None)
        api_user = kwargs.get("api_user", None)
        api_pass = kwargs.get("api_pass", None)
        # Authenticate on vCenter
        vsphere_api = vSphereAPI(api_url, api_user, api_pass, verify_ssl)

        vm_cache = {}
        tag_cache = {}

        for vm in vsphere_api.get_all_vms():
            vm_cache[vm["name"]] = {}
            vm_tags = vsphere_api.get_vm_tags(vm["vm"])
            for vm_tag in vm_tags["value"]:
                if not vm_tag in tag_cache:
                    tag = vsphere_api.get_vsphere_tag(vm_tag)
                    tag_value = tag["value"]["name"]
                    category = vsphere_api.get_tag_category(tag["value"]["category_id"])
                    tag_cache[vm_tag] = (category["value"]["name"], tag_value)
                tag_id, tag_val = tag_cache[vm_tag]
                vm_cache[vm["name"]].update({tag_id: tag_val})

        return vm_cache

    def process_algorithm(self, source, **kwargs) -> dict:
        """Process source data and return dict"""
        collected_labels = {}
        label_prefix = kwargs.get("label_prefix", None)
        for host, tags in source.items():
            collected_labels[host] = {}
            for tag, value in tags.items():
                if label_prefix:
                    tag = f"{label_prefix}/{tag}"
                collected_labels[host].update({tag.strip(): value.strip()})
        return collected_labels
