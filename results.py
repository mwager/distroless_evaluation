



# TODO: ignore certain vul.TYPE! e.g. {'type': 'nodejs', 'name': 'npm'}
# # die interessieren UNS NICHT!!!!!!!!! aber mal sansehen vorher
# # ALSO: die werden evtl mal erwähnt und kommen in die statistik. ABER sie werden NICHT ANALYSIERT!!!!!!!!!!

# # und:

# why this??? liegt das an from scratch!??!?!
# chisel-go:latest  39
# YESSSSSSSS {'type': '-', 'name': '-'}
# YESSSSSSSS {'type': '-', 'name': '-'}
# YESSSSSSSS {'type': '-', 'name': '-'}
# YESSSSSSSS {'type': '-', 'name': '-'}
# YESSSSSSSS {'type': '-', 'name': '-'}
# YESSSSSSSS {'type': '-', 'name': '-'}

# also rausfinden wenn kein TYPE da. warum!??!?!


# Also: to be ignored:

# if "packagePath": "/usr/local/bin/node", OR TYPE["type"] == 'nodejs' or packageName contains npm
# -> keine weitere analyse!
# ABER: COUNT IT! damit wir swissen wieviele nodejs related zb



"""
This file will analyse results/FINAL.json ...
"""
import json
from helpers import prettyPrint, die, readFile, printImageTable

exploitAndImpactData = {}
data = readFile('results/FINAL.json', True)

imagesNoVulns = []
imageCountNoCriticalVulns = 0
imagesCriticalOrHighVulns = []
amountCriticalVulns = 0
amountHighVulns = 0
amountMediumVulns = 0
amountLowVulns = 0

exploits = {}
knownExploits = {}

# for stats we are not interested in runtime issues (like nodejs, php packages etc)
# UPDATE: we ARE interested in runtime issues. if an app is using a go image and go has a critical vuln, this IS IMPORTANT!
# So we want to categorize based on "os" and "runtime" !!!
# we want to focus only on base image/distro related vulns
def weCanIgnoreThisVulnForManualAnalysis(vul):
    if vul["packageName"] == "go" or vul["packageName"] == "nodejs":
        return True

    if vul["TYPE"]["type"] != "os":
        return True

printImageTable(data)
die("OK")

for image in data:
    # print("=== IMAGE: " + image["meta"]["name"] + ' ' + image["meta"]["distro"])
    distribution = image["vulnerabilityDistribution"]
    # print(distribution)



    imagename = (image["meta"]["name"]).replace("_", "\\_").replace('gcr.io-distroless-', 'distroless-').replace('cgr.dev-chainguard-', 'chainguard-').replace('registry.access.redhat.com-', 'redhat-')

    print(imagename + " & " + str(distribution["total"]) + ' & ' + str(distribution["critical"]) + ' & ' + str(distribution["high"]) + ' & ' + str(distribution["medium"]) + ' & ' + str(distribution["low"]) + '\\\\')

    for vul in image["vulns"]:
        CVE = vul["id"]
        severity = vul["severity"]
        severityCVSS = vul["severity"]

        # if weCanIgnoreThisVulnForManualAnalysis(vul):
        #     continue

        # tmp
        # if vul["packageName"] =="db5.3":
        #     continue

        exploitAndImpactData[CVE] = {
            "exploitabilityScore": 0,
            "impactScore": 0
        }

        if "cveDataFetched" in vul and "vulnerabilities" in vul["cveDataFetched"] and len(vul["cveDataFetched"]["vulnerabilities"]) > 0:
            vulCVSS = vul["cveDataFetched"]["vulnerabilities"][0]
            if "cve" in vulCVSS:
                vulCVSS = vulCVSS["cve"]
                if "metrics" in vulCVSS and "cvssMetricV31" in vulCVSS["metrics"]:
                    cvssMetricV31 = vulCVSS["metrics"]["cvssMetricV31"][0]

                    # TODO. why is there such a diff between the twistcli severities and the cvss ones?
                    # For now: better to trust twistcli!
                    # problem is with twistcli, critical and high ONLY in node 16 images!!!
                    # severity = cvssMetricV31["cvssData"]["baseSeverity"].lower()
                    severityCVSS = cvssMetricV31["cvssData"]["baseSeverity"].lower()

                    # print(cvssMetricV31)
                    exploitAndImpactData[CVE] = {
                        "exploitabilityScore": cvssMetricV31["exploitabilityScore"],
                        "impactScore": cvssMetricV31["impactScore"],
                    }


        # if severity == "critical":
        #     print(vul["packageName"], vul["cvss"], CVE, vul["imageFoundIn"])

        #     if vul["packageName"] == "openssl":
        #         prettyPrint(vul)

        # TODO!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
        if "exploitData" in vul:
            exploits[CVE] = {}
            exploits[CVE]["exploitData"] = vul
            # prettyPrint(vul["exploitData"])

        if "knownExploit" in vul:
            knownExploits[CVE] = {}
            knownExploits[CVE]["exploitData"] = vul
            # prettyPrint(vul["knownExploit"])


        if severity == "medium" and severity != severityCVSS:
            prettyPrint(vul)
            die("TODO evaluate")

        if severity == "critical":
            print(vul["packageName"], vul["cvss"], CVE, vul["imageFoundIn"])

        # if severityCVSS == "critical":
        #     print(vul["packageName"], vul["cvss"], CVE, vul["imageFoundIn"])


        if (severity == "critical"):
            amountCriticalVulns = amountCriticalVulns + 1
        if (severity == "high"):
            amountHighVulns = amountHighVulns + 1
        if (severity == "medium"):
            amountMediumVulns = amountMediumVulns + 1
        if (severity == "low"):
            amountLowVulns = amountLowVulns + 1


    if distribution["total"] == 0:
        imagesNoVulns.append(image["meta"]["name"])
    if distribution["critical"] == 0:
        imageCountNoCriticalVulns = imageCountNoCriticalVulns + 1

    if distribution["critical"] > 0 or distribution["high"] == 0:
        imagesCriticalOrHighVulns.append(image["meta"]["name"])



die("TODO ORDER!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!")
LEN = len(data)
print("\n\n\n=========================\nEinfach beschreiben was ich seh:")
print("========================")
print("# of images to analyse: ", LEN)
print("# of images WITHOUT ANY vulns: ", str(len(imagesNoVulns)) + ' of '+ str(LEN) + '('+ str(len(imagesNoVulns) /LEN * 100.0) +')', imagesNoVulns)

print("# of images WITHOUT ANY CRITICAL vulns: ", imageCountNoCriticalVulns, "\n")

print("# of images with HIGH or CRITICAL vulns: ", str(len(imagesCriticalOrHighVulns)) + ' of '+ str(LEN) + ' ('+ str(len(imagesCriticalOrHighVulns) / LEN * 100.0) +')', imagesCriticalOrHighVulns)

# TODO: eine tabelle mit den ZERO FINDINGS
# Eine Tabelle mit den critical or high (medium/low interessiert uns für RQ1 NICHT, oder doch? evtl extra table)
# TODO: stats mit vuln counts und image name
# TODO: tabellen für latex :) in helpers.py einfach print dann :D

exploitableValues = []
impactValues = []
for cve in exploitAndImpactData:
    exploitableValues.append(exploitAndImpactData[cve]["exploitabilityScore"])
    impactValues.append(exploitAndImpactData[cve]["impactScore"])
# TODO was bedeuten diese zahlen?
print("\n======= exloitability und impact score max value: ", max(exploitableValues), max(impactValues))
# print(exploitAndImpactData)

print("\nVULN SEVERITY COUNTS (critical, high, medium, low): ", amountCriticalVulns, amountHighVulns, amountMediumVulns, amountLowVulns)

print("\n==================== EDB mappings and known exploits count: ")
e = 0
for cve in exploits:
    e = e + 1

e2 = 0
for cve in knownExploits:
    e2 = e2 + 1
print(e, e2)

print("TODO: ALLE exploits found manuell näher analysieren dann, EASY! sind nicht viele. das wird RQ2 !!!")
