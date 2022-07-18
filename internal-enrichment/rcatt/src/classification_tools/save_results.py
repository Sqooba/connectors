##########################################################
#                 SAVE RESULTS FUNCTIONS                 #
##########################################################
# rcATT is a tool to prediction tactics and techniques
# from the ATT&CK framework, using multilabel text
# classification and post processing.
# Version:    1.00
# Author:     Valentine Legoy
# Date:       2019_10_22
# Functions to save the results either in a JSON file
# under the STIX format or in the training set.

import csv
import datetime

import stix2 as stx

import classification_tools as clt


def save_results_in_file(report, title, date, ttps):
    """
    Save prediction in a JSON file under STIX format
    """
    publication_date = datetime.datetime.strptime(date, "%Y-%m-%d")
    stix_report = stx.Report(
        type="report",
        labels=["threat-report"],
        name=title,  # request from user
        published=publication_date,  # timestamp
        description=report,  # report
        object_refs=ttps,
        allow_custom=True,
    )  # list of related identifiers techniques and tactics
    return stix_report


def save_to_train_set(report, references):
    """
    Save JSON file output by rcATT to training set.
    """
    item_to_add = [report]
    for ttp in clt.ALL_TTPS:
        if ttp in references:
            item_to_add.append("1")
        else:
            item_to_add.append("0")
    with open("classification_tools/data/training_data_added.csv", "a") as f:
        writer = csv.writer(f, quoting=csv.QUOTE_ALL, lineterminator="\n")
        writer.writerow(item_to_add)
