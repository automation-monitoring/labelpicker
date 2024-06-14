#!/usr/bin/env python3
# -*- encoding: utf-8; py-indent-offset: 4 -*-

# SPDX-FileCopyrightText: © 2023 PL Automation Monitoring GmbH <pl@automation-monitoring.com>
# SPDX-License-Identifier: GPL-3.0-or-later
# This file is part of the Checkmk Labelpicker project (https://labelpicker.mk)


import re
import yaml
import sys
import os
import requests
import json
import base64
import zlib

from abc import ABC, abstractmethod


def _get_automation_secret(username="automation"):
    """Get automation secret for the given user. Default user is automation"""
    omd_root = os.environ["OMD_ROOT"]
    # If automation.secret file for user exists, read credentials from there
    secret_file = f"{omd_root}/var/check_mk/web/{username}/automation.secret"
    if os.path.exists(secret_file):
        secret = open(secret_file).read().strip()
        return secret
    else:
        return False


class Config:
    """Read config data"""

    def __init__(self, config_file):
        if config_file == True:
            # Use default config file
            omd_root = os.environ["OMD_ROOT"]
            self.config_file = os.path.join(omd_root, "etc", "labelpicker.yml")
        else:
            self.config_file = config_file

    def get_cfg(self):
        """Read config file"""
        # if file ends with .yaml or .yml use yaml loader
        if self.config_file.endswith(".yaml") or self.config_file.endswith(".yml"):
            with open(self.config_file, "r") as f:
                return yaml.safe_load(f)
        else:
            print(f"Unknown config file format: {self.config_file}")
            sys.exit(1)

    def init_cfg(self):
        """Initialize LabelPicker default configuration file"""
        init_cfg = "eJzNVUtv00AQvvtXjJRDEpQ3nCwoVKWCCEqjGpVDU1nb9cRZ1V6vdtdJK8p/Z9aOnZehPXDAkSLvPL755rHjFkD/z4/Xgif4yu4wmQl+jxrOMrkQca6ZFZmEJ9I/4z6VPEsVmd8lCDYDnt7DCrVx7pPBeKAmI+ifwNV58B1OZ1OYGpOjR47HUJ9QomYJ8IJDEfzQiHErVsxiuMg0iliGfMlkjMYHqwm2xZnBkPw3DHzHP3Hp+ZBka9TuvGJJjtX5MAadPzLLTJZrjuaYw4HeWKoUxoJeiVEZShWV9KKtme8B7Pr5cHbxpT8lltJm+pG0n5mO1kxjP8gWtniptc4ZIM2iPHGsVWTC5dqsrUYsNC0HVvYQ3sHbgkKoNC7Ew8mwPJ5sDM8fWKqoTaWNZCkBOqxhZopTYbYLUKpLAkwpIeOSDQ1FaVdi7Lq7x3Hz4abKpQeXCt1EyRiCR2Mx7cE3sr913SiflFm+DGOd5SpciMRS+/yt1oW7aV8IrjNDmPBDyChbGwhQU6NhMhpP4GoCgWUyokK2e9A+lVxQ/SqTy6B9+2K8zuBV12GQuBLNx3/z7+wDdKEzj36++dWtkeZjmE/gPBLFrerD/DXBNRRSaWozt4eFrKajV5dvVhreek0oNCuYPI9x4cw2jWiCWeOdKfKpoRq7tF+UwSuXr7uMdYYbCnuG1WjsCWeM3zO6zHvCznvR7TDF+BKfltaqqFupmzivJA//E9JExWvkaEW8tI7oZkn9s4gVsOcd7Zvr1MHAKlBLJDi3BTldD9SjcSi2m6aY8L1VszK1x+Fq2FM1Ld7axYdcqXL5AjAlwlyTzHXT+MPheESfCfoNNRq7Y0N9JEf6/xBlKRNyYJNoq1bM0NZnUSrkcbpnwbWz5GYVYrnzmnIjdVNetfjlOdUflR2ZC07zhttF1oehTdXQKcqIG24DF/E353M1Hw=="
        # if config file does not exists, create it
        if not os.path.exists(self.config_file):
            # Decode the base64-encoded content
            decoded_content = base64.b64decode(init_cfg)
            decompressed_content = zlib.decompress(decoded_content).decode()

            # Write the decompressed content to a new file
            with open(self.config_file, "w") as file:
                file.write(decompressed_content)

            print(f"Config file {self.config_file} created.")
        else:
            print(f"Config file {self.config_file} already exists. Skipping init.")
        sys.exit(0)


class bcolor:
    def __init__(self):
        self.H1 = "\033[1;30;43m"
        self.H2 = "\033[1;30;47m"
        self.H3 = "\033[1;97;44m"
        self.GREEN = "\033[37;5;82m"
        self.WARNING = "\033[93m"
        self.FAIL = "\033[91m"
        self.ENDC = "\033[0m"
        self.BOLD = "\033[1m"
        self.UNDERLINE = "\033[4m"

    def h1(self, text, width=50):
        width = width - len(text)
        space = " " * (int(width / 2))
        return f"{self.H1}{space}{text}{space}{self.ENDC}"

    def h2(self, text, width=41, indent=2):
        width = width - len(text)
        space = " " * (int(width - indent))
        return f"{self.H2}  {text}{space}{self.ENDC}"

    def h3(self, text, width=20, indent=4):
        width = width - len(text)
        space = " " * (int(width - indent))
        return f"{self.H3}{' '*4}{text}{space}{self.ENDC}"


## Strategy interface
class Strategy(ABC):
    """Source Strategy Interface"""

    @abstractmethod
    def source_algorithm(self) -> None:
        pass

    @abstractmethod
    def process_algorithm(self) -> None:
        pass


class LableDataProcessor:
    """Primary class to handle label data sourcing & processing strategies"""

    def __init__(self, strategy: Strategy = None) -> None:
        if strategy is not None:
            self.strategy = strategy
        else:
            # default strategy
            pass

    def get(self, **kwargs):
        """Get source data"""
        return self.strategy.source_algorithm(**kwargs)

    def process(self, source_data, **kwargs):
        """Process source data
        Returns dict with host as key and labels as value
        Example:

        {'localhost': {'csv/tester': 'Mustermann',
                       'csv/Building': 'A',
                       'csv/Owner': 'Internal-IT',
                       'csv/Room': '305'},
         'testhost1': {'csv/Building': 'A',
                       'csv/Owner': 'Test-Automation',
                       'csv/Room': '305'},
         'testhost2': {'csv/Building': 'B',
                       'csv/Owner': 'Test-Automation',
                       'csv/Room': '104'}}
        """
        return self.strategy.process_algorithm(source_data, **kwargs)


class CMKInstance:
    """Interact with checkmk instance"""

    def __init__(self, url=None, username="automation", password=None):
        """Initialize a REST-API instance. URL, User and Secret can be automatically taken from local site if running as site user.

        Args:
            site_url: the site URL
            api_user: username of automation user account
            api_secret: automation secret

        Returns:
            instance of CMKRESTAPI
        """
        if not url:
            # site_url = _site_url()
            api_version = "1.0"
            # use local siteurl from $HOME/etc/apache/conf.d/listen-port.conf
            omd_root = os.environ["OMD_ROOT"]
            omd_site = os.environ["OMD_SITE"]
            f = open(f"{omd_root}/etc/apache/listen-port.conf", "r").readlines()
            for line in f:
                if line.startswith("Listen"):
                    cmk_local_apache = line.split(" ")[1].strip()
            siteurl = f"http://{cmk_local_apache}/{omd_site}"

            self._api_url = f"{siteurl}/check_mk/api/{api_version}"
        else:
            self._api_url = url

        if not password:
            secret = _get_automation_secret(username)
        else:
            secret = password

        self.headers = {
            "Content-Type": "application/json",
        }

        self._session = requests.session()
        self._session.headers["Authorization"] = f"Bearer {username} {secret}"
        self._session.headers["Accept"] = "application/json"

    def _trans_resp(self, resp):
        try:
            data = resp.json()
        except json.decoder.JSONDecodeError:
            data = resp.text
            print(f"JSONDecodeError for data: {data}")
        return data, resp

    def _request_url(self, method, endpoint, data={}, etag=None):
        headers = self.headers
        if etag is not None:
            headers["If-Match"] = etag

        url = f"{self._api_url}/{endpoint}"
        request_func = getattr(self._session, method.lower())

        return self._trans_resp(
            request_func(
                url,
                json=data,
                headers=headers,
                allow_redirects=False,
            )
        )

    def _get_url(self, endpoint, data={}):
        return self._request_url("GET", endpoint, data)

    def _put_url(self, endpoint, etag, data={}):
        return self._request_url("PUT", endpoint, data, etag)

    def _post_url(self, endpoint, data={}, etag=None):
        return self._request_url("POST", endpoint, data, etag)

    def activate(self, sites=[], force=False):
        """Activates pending changes

        Args:
            sites: On which sites the configuration shall be activated. An empty list means all sites which have pending changes.

        """
        postdata = {"redirect": False, "sites": sites, "force_foreign_changes": force}
        data, resp = self._post_url(
            "domain-types/activation_run/actions/activate-changes/invoke",
            data=postdata,
            etag="*",
        )
        if resp.status_code == 200:
            return data
        else:
            resp.raise_for_status()

    def get_all_hosts(self, effective_attr=False, attributes=True):
        """Gets all hosts from the CheckMK configuration.

        Args:
            effective_attr: Show all effective attributes, which affect this host, not just the attributes which were set on this host specifically. This includes all attributes of all of this host's parent folders.
            attributes: If False do not fetch hosts' data

        Returns:
            hosts: Dictionary of host data or dict of hostname -> URL depending on attributes parameter
        """
        data, resp = self._get_url(
            f"domain-types/host_config/collections/all",
            data={"effective_attributes": "true" if effective_attr else "false"},
        )
        if resp.status_code != 200:
            resp.raise_for_status()
        hosts = {}
        for hinfo_dict in data.get("value", []):
            try:
                id = hinfo_dict["id"]
                hosts[id] = hinfo_dict["extensions"]
            except KeyError:
                pass
        return hosts

    def get_host(self, hostname):
        """Get current host configuration

        Args:
            hostname: cmk hostname

        Return:
            data: {hostconfig}
        """
        data, resp = self._get_url(
            f"objects/host_config/{hostname}", data={"effective_attributes": "false"}
        )
        if resp.status_code == 200:
            return data
        resp.raise_for_status()

    def get_etag(self, hostname):
        """Get current etag value for host"""
        data, resp = self._get_url(
            f"objects/host_config/{hostname}", data={"effective_attributes": "false"}
        )
        if resp.status_code == 200:
            return resp.headers["etag"]
        resp.raise_for_status()

    def edit_host(
        self, hostname, etag=None, set_attr={}, update_attr={}, unset_attr=[]
    ):
        """Edit a host in the CheckMK configuration.

        Args:
            hostname: name of the host
            etag: (optional) etag value, if not provided the host will be looked up first using get_host().
            set_attr: Replace all currently set attributes on the host, with these attributes. Any previously set attributes which are not given here will be removed.
            update_attr: Just update the hosts attributes with these attributes. The previously set attributes will not be touched.
            unset_attr: A list of attributes which should be removed.

        Returns:
            (data, etag)
            data: host's data
            etag: current etag value
        """

        if set_attr:
            data = {"attributes": set_attr}
        elif update_attr:
            data = {"update_attributes": update_attr}
        elif unset_attr:
            data = {"remove_attributes": unset_attr}

        if not etag:
            etag = self.get_etag(hostname)
        data, resp = self._put_url(
            f"objects/host_config/{hostname}",
            etag,
            data=data,
        )
        if resp.status_code == 200:
            return data, etag
        resp.raise_for_status()

    def host_exists(self, hostname):
        """Check if host exists"""
        host = self.get_host(hostname)
        return host

    def get_labels(self, hostname, object="host"):
        """Get currently defined labels of a host or service object from checkmk"""
        if object == "host":
            host = self.get_host(hostname)
            labels = host["extensions"]["attributes"].get("labels", {})
        elif object == "service":
            # maybe implemented in future
            pass
        return labels

    def set_hostlabels(self, hostname, labels):
        """Set host labels on checkmk"""
        self.edit_host(hostname, update_attr={"labels": labels})

    def update_labels(
        self, orig_labels, labels, label_prefix="hwsw/", enforce_cleanup=False
    ) -> dict:
        """Compare current / original labels with new labels and update if necessary"""
        updated_labels = orig_labels.copy()
        # {'hwsw/os_vendor': 'Ubuntu', 'hwsw/os_version': '20.04', 'test': 'xy'}
        # Cleanup: remove all labels with known prefix from original labels
        for label in orig_labels:
            if enforce_cleanup:
                if label.lower().startswith(label_prefix.lower()):
                    del updated_labels[label]
            else:
                if label.startswith(label_prefix):
                    del updated_labels[label]

        # Update dict with new labels
        updated_labels.update(labels)
        return updated_labels


def case_conversion(label_definitions, params, prefix) -> dict:
    converted = {}
    for host, data in label_definitions.items():
        converted[host] = {}
        for k, v in data.items():
            if "label" in params:
                k = k.split(prefix)[1]
                k = getattr(k, params["label"])()
            if "value" in params:
                v = getattr(v, params["value"])()

            converted[host].update({f"{prefix}{k}": v})
    return converted
