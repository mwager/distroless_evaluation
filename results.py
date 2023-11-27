"""
This file will analyse results/FINAL.json ...
"""
import json, time
from helpers import prettyPrint, die, generateRQ1Chart, readFile, printImageTable, imageIsUsingComponentReduction, genrateEPSSChart, fetch_cve_data

exploitAndImpactData = {}
data = readFile('results/FINAL.json', True)

imagesNoVulns = []
imageCountNoCriticalVulns = 0
imagesCriticalOrHighVulns = []
amountTotalVulns = 0
amountTotalVulnsWithComponentReductionMethods = 0
amountTotalVulnsWithoutComponentReductionMethods = 0
amountCriticalVulns = 0
amountHighVulns = 0
amountMediumVulns = 0
amountLowVulns = 0

exploits = {}
knownExploits = {}

amountOfVulnsWithExploit = 0
amountOSBasedVulns = 0
amountRTBasedVulns = 0
amountOSBasedVulnsWithExploit = 0
amountRTBasedVulnsWithExploit = 0

statsByImage = {}

attackVectorsCounts = {
    "local": 0,
    "network": 0,
    'adjacent': 0,
    'physical': 0
}

attackComplexityCounts = {
    'low': 0,
    'high': 0
}

# for stats we are not interested in runtime issues (like nodejs, php packages etc)
# UPDATE: we ARE interested in runtime issues. if an app is using a go image and go has a critical vuln, this IS IMPORTANT!
# So we want to categorize based on "os" and "runtime" !!!
# we want to focus only on base image/distro related vulns
def weCanIgnoreThisVulnForManualAnalysis(vul):
    if vul["packageName"] == "go" or vul["packageName"] == "nodejs":
        return True

    if vul["TYPE"]["type"] != "os":
        return True

# printImageTable(data)
# die("OK")

# genrateEPSSChart(data)
# die("epss chart generated.")

# generateRQ1Chart(data)
# die("DONE")

for image in data:
    IMAGENAME = image["meta"]["name"] + ' ' + image["meta"]["distro"]

    # print("=== IMAGE: " + image["meta"]["name"] + ' ' + image["meta"]["distro"])
    distribution = image["vulnerabilityDistribution"]
    # print(distribution)

    statsByImage[IMAGENAME] = {
        "total": len(image["vulns"]),
        "critical": distribution["critical"],
        "exploitCount": 0,
        "osBasedVulns": 0,
        "rtBasedVulns": 0
    }

    if imageIsUsingComponentReduction(IMAGENAME):
        amountTotalVulnsWithComponentReductionMethods += distribution["total"]
    else:
        amountTotalVulnsWithoutComponentReductionMethods += distribution["total"]

    for vul in image["vulns"]:
        CVE = vul["id"]
        severity = vul["severity"]
        severityCVSS = vul["severity"]

        amountTotalVulns += 1

        # if weCanIgnoreThisVulnForManualAnalysis(vul):
        #     continue

        # tmp
        # if vul["packageName"] =="db5.3":
        #     continue

        exploitAndImpactData[CVE] = {
            "exploitabilityScore": 0,
            "impactScore": 0
        }

        if vul["TYPE"]["type"] == "os":
            amountOSBasedVulns += 1
            statsByImage[IMAGENAME]["osBasedVulns"] += 1
        else:
            amountRTBasedVulns += 1
            statsByImage[IMAGENAME]["rtBasedVulns"] += 1

        if vul["exploit"] == True:
            amountOfVulnsWithExploit += 1
            statsByImage[IMAGENAME]["exploitCount"] += 1

            if vul["TYPE"]["type"] == "os":
                amountOSBasedVulnsWithExploit += 1
            else:
                amountRTBasedVulnsWithExploit += 1

        if (vul["severity"] == "critical" or vul["severity"] == "high" or vul["severity"] == "important"):
            if vul["exploit"] == True:
                print("GOT EXPLOIT", vul["TYPE"], CVE, vul["imageFoundIn"], severity)
            else:
                print("WITHOUT EXPLOIT", vul["TYPE"], CVE, vul["imageFoundIn"], severity)

        if "cveDataFetched" in vul and "vulnerabilities" in vul["cveDataFetched"] and len(vul["cveDataFetched"]["vulnerabilities"]) > 0:
            vulCVSS = vul["cveDataFetched"]["vulnerabilities"][0]
            if "cve" in vulCVSS:
                vulCVSS = vulCVSS["cve"]
                if "metrics" in vulCVSS and "cvssMetricV31" in vulCVSS["metrics"]:
                    cvssMetricV31 = vulCVSS["metrics"]["cvssMetricV31"][0]

                    # why is there such a diff between the twistcli severities and the cvss ones?
                    # bc twistcli uses environmental and vendor based scores!
                    severityCVSS = cvssMetricV31["cvssData"]["baseSeverity"].lower()

                    attackVector = cvssMetricV31["cvssData"]["attackVector"].lower()
                    attackComplexity = cvssMetricV31["cvssData"]["attackComplexity"].lower()

                    attackVectorsCounts[attackVector] += 1
                    attackComplexityCounts[attackComplexity] += 1

                    # print(cvssMetricV31)
                    exploitAndImpactData[CVE] = {
                        "exploitabilityScore": cvssMetricV31["exploitabilityScore"],
                        "impactScore": cvssMetricV31["impactScore"],
                    }


        # if severity == "critical":
        #     print(vul["packageName"], vul["cvss"], CVE, vul["imageFoundIn"])

        #     if vul["packageName"] == "openssl":
        #         prettyPrint(vul)

        if "exploitData" in vul:
            exploits[CVE] = {}
            exploits[CVE]["exploitData"] = vul
            # prettyPrint(vul["exploitData"])

        if "knownExploit" in vul:
            knownExploits[CVE] = {}
            knownExploits[CVE]["exploitData"] = vul
            # prettyPrint(vul["knownExploit"])


        # if severity == "medium" and severity != severityCVSS:
        #     prettyPrint(vul)
        #     die("TODO evaluate")

        # if severity == "critical":
        #     print(vul["packageName"], vul["cvss"], CVE, vul["imageFoundIn"], severity)

        # if severityCVSS == "critical":
        #     print(vul["packageName"], vul["cvss"], CVE, vul["imageFoundIn"])

        if (severity == "critical"):
            amountCriticalVulns = amountCriticalVulns + 1
        if (severity == "high" or severity == "important"):
            amountHighVulns = amountHighVulns + 1
        if (severity == "medium" or severity == "moderate"):
            amountMediumVulns = amountMediumVulns + 1
        if (severity == "low"):
            amountLowVulns = amountLowVulns + 1


    if distribution["total"] == 0:
        imagesNoVulns.append(image["meta"]["name"])
    if distribution["critical"] == 0:
        imageCountNoCriticalVulns = imageCountNoCriticalVulns + 1

    if distribution["critical"] > 0 or distribution["high"] == 0:
        imagesCriticalOrHighVulns.append(image["meta"]["name"])



print("\n===============================================")
print("==================== RESULTS ====================")
print("=================================================")

LEN = len(data)
print("\n\n\n=========================\SEE HERE:")
print("========================")
print("# of images to analyse: ", LEN)

print("VULN SEVERITY COUNTS (TOTAL, critical, high, medium, low): ", amountTotalVulns, amountCriticalVulns, amountHighVulns, amountMediumVulns, amountLowVulns, "\n")



print("# of images WITHOUT ANY vulns: ", str(len(imagesNoVulns)) + ' of '+ str(LEN) + '('+ str(len(imagesNoVulns) /LEN * 100.0) +')', imagesNoVulns)

print("# of images WITHOUT ANY CRITICAL vulns: ", imageCountNoCriticalVulns, "\n")

print("# of images with HIGH or CRITICAL vulns: ", str(len(imagesCriticalOrHighVulns)) + ' of '+ str(LEN) + ' ('+ str(len(imagesCriticalOrHighVulns) / LEN * 100.0) +')', imagesCriticalOrHighVulns)

print("\n==================== RQ1: ", amountTotalVulnsWithComponentReductionMethods, amountTotalVulnsWithoutComponentReductionMethods, "REDUCTION: ")



exploitableValues = []
impactValues = []
for cve in exploitAndImpactData:
    exploitableValues.append(exploitAndImpactData[cve]["exploitabilityScore"])
    impactValues.append(exploitAndImpactData[cve]["impactScore"])

print("\n======= exloitability und impact score max value: ", max(exploitableValues), max(impactValues))
# print(exploitAndImpactData)

print("\n==================== EDB mappings and known exploits count: ")
e = 0
for cve in exploits:
    e = e + 1

e2 = 0
for cve in knownExploits:
    e2 = e2 + 1
print(e, e2)

print("\n==================== TABLES:")
print("OS based: ", amountOSBasedVulns)
print("Runtime based: ", amountRTBasedVulns)
print("\n==================== Count of vulns WITH EXPLOIT POC: ")
print("TODO statistics / discussion: amountOfVulnsWithExploit", amountOfVulnsWithExploit)
print("OS based which got exploit: ", amountOSBasedVulnsWithExploit)
print("Runtime based which got exploit: ", amountRTBasedVulnsWithExploit)

print("\n==================== TABLES stats by image:")
# prettyPrint(statsByImage)
for image in statsByImage:
    if statsByImage[image]["exploitCount"] > 0:
        print(image, " has ", statsByImage[image]["exploitCount"], " exploits")



print("\n==============\nattackVectorsCounts and attackComplexityCounts")
print(attackVectorsCounts)
print(attackComplexityCounts)

