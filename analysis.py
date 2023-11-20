"""
This file will analyse all JSON files generated from scan.py and add additional information
to the scanner findings like CVE metadata or public exploit information.

Finally it will write a file called FINAL.json which can be used for final analysis
"""
from helpers import die, readFile, writeFile, prettyPrint, readTwistcliFile, fetch_cve_data, fetch_exploits, fetchExploitFromTwistcliVuln, fetchEPSS
import glob, json
import time, requests
import csv

RESULT_FOLDER = "results/twistcli"
files = glob.glob(RESULT_FOLDER + '/*')
FINAL = []

print("# of JSON files to analyse: ", len(files))

KEVCatalog = response = requests.get('https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json').json()

print("length of CISA known exploited vulns catalog", len(KEVCatalog["vulnerabilities"]))

def findKnownExploitation(cve):
    for vul in KEVCatalog["vulnerabilities"]:
        if vul["cveID"] == cve:
            return vul

blackMarketExploits = []
with open('./BlackMarketExploits.csv') as csv_file:
    csv_reader = csv.reader(csv_file, delimiter=',')
    for row in csv_reader:
        blackMarketExploits.append(row)

def findBlackMarketExploit(cve):
    for row in blackMarketExploits:
        if cve in row[3]:
            return row

# files = files[0:5]
for filepath in files:
    data = readTwistcliFile(filepath)
    # data["vulnerabilityDistribution"]["total"]

    print(data["meta"]["name"], data["meta"]["distro"], " =====> COUNT: ", data["vulnerabilityDistribution"]["total"])

    packages = data["packages"]
    applications = data["applications"]

    for vul in data["vulns"]:
        CVE = vul["id"]
        # filter only high/critical or with exploit?
        # NO. in FINAL we want ALL!

        # prettyPrint(vul)

        # we want the image this vuln was found in at every vuln bc this is important for assessment
        vul["imageFoundIn"] = data["meta"]["name"] + ' / ' + data["meta"]["distro"]

        # check the vuln TYPE
        pckName = vul["packageName"]
        vul["TYPE"] = {
            "type": "-",
            "name": "-" # means no mapping found
        }

        for pck in packages:
            if pckName == pck["name"]:
                vul["TYPE"]["type"] = pck["type"]
                vul["TYPE"]["name"] = pck["name"]

        #if (vul["severity"] == "critical" or vul["severity"] == "high"):


        # twistcli provides exploit info! Additional analyse will be manually
        vul["exploit"] = fetchExploitFromTwistcliVuln(vul)
        vul["epss"] = fetchEPSS(CVE)
        print("EPSS", vul["epss"])
        time.sleep(1)


        # =================================================================================
        # fetch additional CVE meta data
        cveData = fetch_cve_data(CVE)
        if (cveData):
            print("GOT CVE DATA!")
            vul["cveDataFetched"] = cveData
        # we need to sleep a bit to prevent rate limits with NVD CVE API
        time.sleep(1)

        # All not needed as we are just using the EPSS SCORE!
        # black market exploits
        # bmExploit = findBlackMarketExploit(CVE)
        # if bmExploit:
        #     # never found :/
        #     print("YYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYY", bmExploit)
        #     vul["blackMaketExploit"] = bmExploit

        # SYM exploits in the wild
        #use web scraping here: https://www.broadcom.com/support/security-center/attacksignatures

        # search exploits available for CVE
        # try:
        #     if not CVE in ["CVE-2020-1751", "CVE-2022-2509", "CVE-2022-3626"]:
        #         exploitData = json.loads(fetch_exploits(CVE))

        #         if (len(exploitData["RESULTS_EXPLOIT"]) > 0):
        #             vul["exploitData"] = exploitData["RESULTS_EXPLOIT"]
        #             print("\nGOT EXPLOIT", exploitData, CVE)
        # except:
        #     print("error fetching EDB ", CVE)

        # TODO !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
        # # USE MORE:
        #https://docs.docker.com/scout/advisory-db-sources/

        # known = findKnownExploitation(CVE)
        # if known:
        #     vul["knownExploit"] = known
        #     print("\nGOT knownExploit", vul["knownExploit"], CVE)
        # =================================================================================

    FINAL.append(data)

writeFile("results/FINAL.json", json.dumps(FINAL, indent=2))
print("DONE")