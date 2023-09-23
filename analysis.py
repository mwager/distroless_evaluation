"""
This file will analyse all JSON files generated from scan.py and add additional information
to the scanner findings like CVE metadata or public exploit information.

Finally it will write a file called FINAL.json which can be used for final analysis
"""
from helpers import die, readFile, writeFile, prettyPrint, readTwistcliFile, fetch_cve_data, fetch_exploits
import glob, json


RESULT_FOLDER = "results/twistcli"
files = glob.glob(RESULT_FOLDER + '/*')
FINAL = []

print("# of JSON files to analyse: ", len(files))

# files = files[0:5]
for filepath in files:
    data = readTwistcliFile(filepath)
    # data["vulnerabilityDistribution"]["total"]

    print(data["meta"]["name"], data["meta"]["distro"], data["vulnerabilityDistribution"]["total"])

    packages = data["packages"]
    applications = data["applications"]

    for vul in data["vulns"]:
        # prettyPrint(vul)

        # check the vuln TYPE (important as we ignore all runtime based vulns! We are NOT interested in issues like
        # JDK related or e.g. node v16 has critical vuln. We are ONLY interested in base image related "os" type vulns!)
        pckName = vul["packageName"]
        vul["TYPE"] = {
            "type": "-",
            "name": "-" # means no mapping found
        }

        for pck in packages:
            if pckName == pck["name"]:
                vul["TYPE"]["type"] = pck["type"]
                vul["TYPE"]["name"] = pck["name"]

        print("YESSSSSSSS", vul["TYPE"])


        # EDB: https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2022-3515
        # TODO: exploitabilityScore und impactScore beschreiben im paper!!!!!!!!!!!!!!!
        # How likely a vulnerability will be exploited is not the same as a vulnerability being actively exploited.
        # TODO EKITS? http://seconomicsproject.eu/sites/default/files/seconomics/public/content-files/downloads/Comparing%20Vulnerabilities%20and%20Exploits%20using%20case%20control%20studies.pdf
        # # https://contagiodump.blogspot.com/2010/06/overview-of-exploit-packs-update.html

        # fetch additional CVE meta data
        cveData = fetch_cve_data(vul["id"])
        if (cveData):
            vul["cveDataFetched"] = cveData

        # search exploits available for CVE
        try:
            exploitData = json.loads(fetch_exploits(vul["id"]))

            if (len(exploitData["RESULTS_EXPLOIT"]) > 0):
                vul["exploitData"] = exploitData["RESULTS_EXPLOIT"]
        except:
            vul["exploitData"] = []

        # print("\n")

    FINAL.append(data)

writeFile("results/FINAL.json", json.dumps(FINAL, indent=2))


print("========================")
print("Einfach beschreiben was ich seh:")
print("Total # of base images scanned: ", len(files))
print("TODO: ALLE exploits found manuell näher analysieren dann, EASY! sind nicht viele. das wird RQ2 !!!")
