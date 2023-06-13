#!/usr/bin/env python3
# -*- encoding: utf-8; py-indent-offset: 4 -*-

# SPDX-FileCopyrightText: © 2023 PL Automation Monitoring GmbH <pl@automation-monitoring.com>
# SPDX-License-Identifier: GPL-3.0-or-later
# This file is part of the Checkmk Labelpicker project (https://labelpicker.mk)

from labelpicker.labelpicker_base import Strategy
import os
import csv


class lpds_csv(Strategy):
    """CSV strategy"""

    def source_algorithm(self, **kwargs) -> dict:
        parsed = []
        csv_files = kwargs.get("csv_files", [])

        for csv_file in csv_files:
            if os.path.isfile(csv_file):
                # read csv file
                with open(csv_file, "r") as f:
                    reader = csv.reader(f, delimiter=";")
                    for row in reader:
                        # add row to parsed list but skip first row (header)
                        if not reader.line_num == 1:
                            parsed.append(row)
        return parsed

    def process_algorithm(self, source, **kwargs) -> dict:
        """Process source data and return dict"""
        collected_labels = {}
        label_prefix = kwargs.get("label_prefix", None)
        for row in source:
            host = row[0]
            collected_labels[host] = {}
            # update collected_labels with host and label
            for label in row[1].split(","):
                k, v = label.split(":")
                if label_prefix:
                    k = f"{label_prefix}/{k}"
                collected_labels[host].update({k.strip(): v.strip()})

        return collected_labels
