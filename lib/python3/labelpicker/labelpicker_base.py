#!/usr/bin/env python3
# -*- encoding: utf-8; py-indent-offset: 4 -*-

# SPDX-FileCopyrightText: © 2023 PL Automation Monitoring GmbH <pl@automation-monitoring.com>
# SPDX-License-Identifier: GPL-3.0-or-later
# This file is part of the Checkmk Labelpicker project (https://labelpicker.mk)


import re
import yaml
import sys

# import checkmkapi
from checkmkapi import CMKRESTAPI
from abc import ABC, abstractmethod
import time


class Config:
    """Read config data"""

    def __init__(self, config_file):
        self.config_file = config_file
        self.read = self._read_config()

    def _read_config(self):
        """Read config file"""
        # if file ends with .yaml or .yml use yaml loader
        if self.config_file.endswith(".yaml") or self.config_file.endswith(".yml"):
            with open(self.config_file, "r") as f:
                return yaml.safe_load(f)
        elif self.config_file.endswith(".conf"):
            return eval(open(args.config, "r").read())
        else:
            print(f"Unknown config file format: {self.config_file}")
            sys.exit(1)


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


class WebView(Strategy):
    """Webview strategy"""

    def source_algorithm(self) -> dict:
        print("Webview strategy")
        return {}

    def process_algorithm(self) -> dict:
        print("Webview strategy")
        return {}


class LableDataProcessor:
    """Primary class to handle label data sourcing & processing strategies"""

    def __init__(self, strategy: Strategy = None) -> None:
        if strategy is not None:
            self.strategy = strategy
        else:
            # default strategy
            self.strategy = WebView()

    def get(self, **kwargs):
        """Get source data"""
        return self.strategy.source_algorithm(**kwargs)

    def process(self, source_data, **kwargs):
        """Process source data
        Returns dict with host as key and labels as value
        Example:  {'hwsw/hw_vendor': 'VMware, Inc.',
                   'hwsw/os_vendor': 'Rhel',
                   'hwsw/os_version': 'Red Hat Enterprise'}"""

        return self.strategy.process_algorithm(source_data, **kwargs)


class CMKInstance(CMKRESTAPI):
    """Interact with checkmk instance"""

    def __init__(self, url=None, username=None, password=None):
        """Initialize Roberts CMK REST API Class"""
        super().__init__(url, username, password)

    def activate(self, sites=[], force=False):
        """Activates pending changes

        Args:
            sites: On which sites the configuration shall be activated. An empty list means all sites which have pending changes.

        Returns:
            (data, etag): usually both empty
        """
        # sleep for 2s to let API settle down
        time.sleep(2)
        postdata = {"redirect": False, "sites": sites, "force_foreign_changes": force}
        data, etag, resp = self._post_url(
            "domain-types/activation_run/actions/activate-changes/invoke",
            data=postdata,
        )
        if resp.status_code == 200:
            # print("Activation successful")
            return data, etag
        if resp.status_code == 302:
            if data.get("domainType") == "activation_run":
                for link in data.get("links", []):
                    if link.get("rel") == "urn:com.checkmk:rels/wait-for-completion":
                        d, e, r = self._wait_for_activation(link.get("href"))
                        if r.status_code == 204:
                            return d, e
                        r.raise_for_status()
        resp.raise_for_status()

    def get_all_hosts(self, effective_attr=False, attributes=True):
        """Gets all hosts from the CheckMK configuration.

        Args:
            effective_attr: Show all effective attributes, which affect this host, not just the attributes which were set on this host specifically. This includes all attributes of all of this host's parent folders.
            attributes: If False do not fetch hosts' data

        Returns:
            hosts: Dictionary of host data or dict of hostname -> URL depending on aatributes parameter
        """
        data, etag, resp = self._get_url(
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

    def host_exists(self, hostname):
        """Check if host exists"""
        host, etag = self.get_host(hostname)
        return host

    def get_labels(self, hostname, object="host"):
        """Get currently defined labels of a host or service object from checkmk"""
        if object == "host":
            host, etag = self.get_host(hostname)
            labels = host["extensions"]["attributes"].get("labels", {})
        elif object == "service":
            # maybe implemented in future
            pass
        return labels

    def set_hostlabels(self, hostname, labels):
        """Set host labels on checkmk"""
        self.edit_host(hostname, update_attr={"labels": labels})

    def update_labels(self, orig_labels, labels, label_prefix="hwsw/") -> dict:
        """Compare current / original labels with new labels and update if necessary"""
        updated_labels = orig_labels.copy()
        # {'hwsw/os_vendor': 'Ubuntu', 'hwsw/os_version': '20.04', 'test': 'xy'}
        # Cleanup: remove all labels with known prefix from original labels
        for label in orig_labels:
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
