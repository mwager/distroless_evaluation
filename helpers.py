"""
Some helpers used in main.py
"""
import json, unittest, requests, os
import plotly.express as px
import pandas as pd
import plotly.graph_objects as go
import numpy as np
from plotly.data import tips
import subprocess

def prettyPrint(json_obj):
    print (json.dumps(json_obj, indent=2))

def die(str):
    print(str)
    exit()

def writeFile(filename, content):
    file = open(filename, 'w', encoding="utf-8")
    file.write(content) #Merged
    file.close()

def readFile(filename, asJSON):
    f = open(filename, 'r', encoding="utf-8")

    if asJSON:
        ret = json.load(f)
        f.close()
        return ret

    with open(filename) as f:
        lines =  f.readlines()
        f.close()
        return lines


# see https://plotly.com/python/line-charts/
def writeChartImage(data):
    # data = [
    #     {"baseImage": "node:latest", "vulnCountTotal": 46},
    #     {"baseImage": "distroless:node", "vulnCountTotal": 3}
    # ]

    x = []
    y = []
    for item in data:
        x.append(item["baseImage"])
        y.append(item["vulnCountTotal"])

    fig = px.bar(x=x, y=y)

    fig.write_image("images/fig1.png")


# Fetch CVE data from NIST NVD API
def fetch_cve_data(cve_id):
    try:
        response = requests.get(f'https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}')
        return response.json()
    except requests.exceptions.RequestException as error:
        print(f'Failed to fetch CVE data for {cve_id}: {error}')
        return None
    except:
        return None

def execute_command(command):
    try:
        # Run the command and capture stdout and stderr
        result = subprocess.run(
            command,
            shell=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            universal_newlines=True,
            check=True,  # Raise an exception for non-zero return codes
        )
        return result.stdout or result.stderr
    except subprocess.CalledProcessError as e:
        # If the command exits with a non-zero status code, you can handle the error here
        print(f"Error executing command: {e}")
        return e.stderr
    except:
        return None


# Fetch exploits using searchsploit
def fetch_exploits(cve_id):
    try:
        CMD = "cd && sudo searchsploit --json --www --cve " + cve_id
        # os.system(CMD)
        # content = readFile("out.json", True)
        # return content

        return execute_command(CMD)
    except Exception as e:
        print("ERROR: ", e)


def readTrivyFile(path):
    data = readFile(path, True)
    cves = []

    for result in data["Results"]:
        for vuln in result["Vulnerabilities"]:
            cve_id = vuln["VulnerabilityID"]
            print ("checking " + cve_id)
            cves.append(cve_id)

            # Fetch CVE data
            # cve_data = fetch_cve_data(cve_id)
            # if not cve_data:
            #     print('Failed to fetch CVE data. Exiting...')
            #     return

            # print('CVE Data:')
            # # print(cve_data)
            # print(cve_data["vulnerabilities"][0]["cve"]["descriptions"][0]["value"])

            # Fetch exploits
            exploits = fetch_exploits(cve_id.replace("CVE-", ""))
            if not exploits:
                print('Failed to fetch exploits. Exiting...')
                return

            if not "Exploits: No Results" in exploits:
                print('!!!!!!!!!!!!!! >>> Exploits:')
                print(exploits)

"""
Reads a twistcli scan result file and converts it to a normalized/relevant format
"""
def readTwistcliFile(path):
    data = readFile(path, True)
    if (len(data["results"]) == 0):
        return -1

    # always len == 1
    data = data["results"][0]

    results = {
        "meta": {
            "id": data["id"],
            "name": data["name"],
            "distro": data["distro"],
            #"distroRelease": data["distroRelease"],
        },
        "vulnerabilityDistribution": data["vulnerabilityDistribution"],
        "vulns": []
    }

    if "packages" in data:
        results["packages"] = data["packages"]
    else:
        results["packages"] = []

    if "applications" in data:
        results["applications"] = data["applications"]
    else:
        results["applications"] = []

    # e.g. for distroless none at all!
    if (data["vulnerabilityDistribution"]["total"] == 0 or not data["vulnerabilities"]):
        return results

    for vuln in data["vulnerabilities"]:
        results["vulns"].append(vuln)

    return results


# Class is just used for unit testing when this script is executed directly (python3 helpers.py)
class TestHelpers(unittest.TestCase):

    def test_Some_Logic(self):
        self.assertEqual(1, None)


if __name__ == '__main__':
    unittest.main()