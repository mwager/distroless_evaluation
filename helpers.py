"""
Some helpers used in other files
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
        # request API KEY to get 50 reqs within 30secs https://nvd.nist.gov/developers/request-an-api-key
        headers = {'content-type': 'application/json', 'apiKey': "11b20c32-c8ea-4ef7-b74b-48094a8a750b"}
        response = requests.get(f'https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}', headers=headers)

        # CVE_ID could be "PRISMA-123" ...
        if response.status_code != 200:
            print("CVE STATUS CODE ", cve_id, response.status_code)
            return None

        # response = requests.get(f'https://cve.circl.lu/api/cve/${cve_id}')

        return response.json()
    except requests.exceptions.RequestException as error:
        print(f'Failed to fetch CVE data for {cve_id}: {error}')
        return None
    except:
        response.json()
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
        print(f"Error fetching CVE: ", e)
    except Exception as e:
        print("ERROR fetching cve data: ", e)


def fetchExploitFromTwistcliVuln(vul):
    if not "riskFactors" in vul:
        return False

    for r in vul["riskFactors"]:
        if "Exploit exists" in r:
            return True
    return False

def imageIsUsingComponentReduction(imagename):
    if "alpine" in imagename:
        return True
    if "distroless" in imagename:
        return True
    if "chiselled-base_22.04" in imagename:
        return True
    if "ubi-micro" in imagename:
        return True
    if "chainguard" in imagename:
        return True

# Fetch exploits using searchsploit
def fetch_exploits(cve_id):
    try:
        # installed via clone: https://gitlab.com/exploit-database/exploitdb.git
        CMD = "cd && sudo /home/vagrant/exploitdb/searchsploit --json --www --cve " + cve_id
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

def normalizeImageName(name):
    return name.replace("_", "\\_").replace('gcr.io-distroless-', 'distroless-').replace('cgr.dev-chainguard-', 'chainguard-').replace('registry.access.redhat.com-', 'redhat-').replace('-nonroot-amd64-debian11:latest', '').replace(':latest', '').replace('\_latest', ':latest')

# print a table for inclusion into latex
# image vs. all vulns found
def printImageTable(data):
    unordered = []

    print("\\begin{tabular}{||l|l|l|l|l|l||}")
    print("Image & total & critical & high & medium & low \\\\")

    for image in data:
        distribution = image["vulnerabilityDistribution"]
        imagename = normalizeImageName(image["meta"]["name"])
        unordered.append([imagename, distribution["total"], distribution["critical"], distribution["high"], distribution["medium"], distribution["low"]])

    ordered = sorted(unordered, key=lambda x: (x[0], x[1]))

    for item in ordered:
        imagename = item[0]
        distribution = item[1:6]

        print(imagename + " & " + str(distribution[0]) + ' & ' + str(distribution[1]) + ' & ' + str(distribution[2]) + ' & ' + str(distribution[3]) + ' & ' + str(distribution[4]) + '\\\\')

    print("\end{tabular}")

    # data = [
    #     {"baseImage": "node:latest", "vulnCountTotal": 46},
    #     {"baseImage": "distroless:node", "vulnCountTotal": 3}
    # ]

    x = []
    y = []
    for item in ordered:
        x.append(item[0])
        y.append(item[1])

    fig = px.bar(x=x, y=y)
    fig.update_xaxes(title_text='Base images')
    fig.update_yaxes(title_text='Total amount of vulnerabilities')
    fig.write_image("images/total_over_image.png")

    x = []
    y = []
    for item in ordered:
        x.append(item[0])
        y.append(item[2])

    fig = px.bar(x=x, y=y)
    fig.update_xaxes(title_text='Base images')
    fig.update_yaxes(title_text='Amount of critical vulnerabilities')
    fig.write_image("images/critical_over_image.png")

    x = []
    y = []
    for item in ordered:
        x.append(item[0])
        y.append(item[3])

    fig = px.bar(x=x, y=y)
    fig.update_xaxes(title_text='Base images')
    fig.update_yaxes(title_text='Amount of high vulnerabilities')
    fig.write_image("images/high_over_image.png")

    x = []
    y = []
    for item in ordered:
        x.append(item[0])
        y.append(item[4])

    fig = px.bar(x=x, y=y)
    fig.update_xaxes(title_text='Base images')
    fig.update_yaxes(title_text='Amount of medium vulnerabilities')
    fig.write_image("images/medium_over_image.png")

    x = []
    y = []
    for item in ordered:
        x.append(item[0])
        y.append(item[5])

    fig = px.bar(x=x, y=y)
    fig.update_xaxes(title_text='Base images')
    fig.update_yaxes(title_text='Amount of low vulnerabilities')
    fig.write_image("images/low_over_image.png")

# Class is just used for unit testing when this script is executed directly (python3 helpers.py)
class TestHelpers(unittest.TestCase):

    def test_Some_Logic(self):
        self.assertEqual(1, None)


if __name__ == '__main__':
    unittest.main()