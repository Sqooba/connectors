# -*- coding: utf-8 -*-
from operator import itemgetter

import joblib
from colorama import Fore, Style

import classification_tools as clt
import classification_tools.preprocessing as prp


def get_name_with_id(ttps):
    names = []
    for key in ttps:
        # For now, only take attack patterns.
        if key in clt.CODE_TECHNIQUES:
            names.append([clt.NAME_TECHNIQUES[clt.CODE_TECHNIQUES.index(key)], key])
    return names


def predict(report_to_predict_file):
    """
    Predict tactics and techniques from a report in a txt file.
    """
    # parse text from file
    report_to_predict = ""
    with open(
        report_to_predict_file, "r", newline="", encoding="ISO-8859-1"
    ) as filetoread:
        data = filetoread.read()
        report_to_predict = prp.remove_u(data)

    # load postprocessing and min-max confidence score for both tactics and techniques predictions
    parameters = joblib.load("classification_tools/data/configuration.joblib")
    min_prob_tactics = parameters[2][0]
    max_prob_tactics = parameters[2][1]
    min_prob_techniques = parameters[3][0]
    max_prob_techniques = parameters[3][1]

    pred_tactics, predprob_tactics, pred_techniques, predprob_techniques = clt.predict(
        report_to_predict, parameters
    )

    # change decision value into confidence score to display
    for i in range(len(predprob_tactics[0])):
        conf = (predprob_tactics[0][i] - min_prob_tactics) / (
            max_prob_tactics - min_prob_tactics
        )
        if conf < 0:
            conf = 0.0
        elif conf > 1:
            conf = 1.0
        predprob_tactics[0][i] = conf * 100
    for j in range(len(predprob_techniques[0])):
        conf = (predprob_techniques[0][j] - min_prob_techniques) / (
            max_prob_techniques - min_prob_techniques
        )
        if conf < 0:
            conf = 0.0
        elif conf > 1:
            conf = 1.0
        predprob_techniques[0][j] = conf * 100

    print(pred_tactics)
    # prepare results to display
    ttps = []
    to_print_tactics = []
    to_print_techniques = []
    for ta in range(len(pred_tactics[0])):
        if pred_tactics[0][ta] == 1:
            ttps.append(clt.CODE_TACTICS[ta])
            to_print_tactics.append([1, clt.NAME_TACTICS[ta], predprob_tactics[0][ta]])
        else:
            to_print_tactics.append([0, clt.NAME_TACTICS[ta], predprob_tactics[0][ta]])
    for te in range(len(pred_techniques[0])):
        if pred_techniques[0][te] == 1:
            ttps.append(clt.CODE_TECHNIQUES[te])
            to_print_techniques.append(
                [1, clt.NAME_TECHNIQUES[te], predprob_techniques[0][te]]
            )
        else:
            to_print_techniques.append(
                [0, clt.NAME_TECHNIQUES[te], predprob_techniques[0][te]]
            )
    to_print_tactics = sorted(to_print_tactics, key=itemgetter(2), reverse=True)
    to_print_techniques = sorted(to_print_techniques, key=itemgetter(2), reverse=True)
    print("Predictions for the given report are : ")
    print("Tactics :")
    for tpta in to_print_tactics:
        if tpta[0] == 1:
            print(Fore.YELLOW + "" + tpta[1] + " : " + str(tpta[2]) + "% confidence")
        else:
            print(Fore.CYAN + "" + tpta[1] + " : " + str(tpta[2]) + "% confidence")
    print(Style.RESET_ALL)
    print("Techniques :")
    for tpte in to_print_techniques:
        if tpte[0] == 1:
            print(Fore.YELLOW + "" + tpte[1] + " : " + str(tpte[2]) + "% confidence")
        else:
            print(Fore.CYAN + "" + tpte[1] + " : " + str(tpte[2]) + "% confidence")
    print(Style.RESET_ALL)
    ttps_with_id = get_name_with_id(ttps)
    print(f"ttps with names and ids: {ttps_with_id}")
    return ttps_with_id
