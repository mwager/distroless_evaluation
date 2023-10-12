"""
This file defines all relevant base images which shall be analysed in the thesis.

First a simple docker file will be generated in order to build each image.

Then all images will be scanned and the scan results will be written to disk (json files).
"""
import os, json, configparser, requests
from helpers import die, writeFile, readFile, readTwistcliFile, execute_command, prettyPrint, writeChartImage
import subprocess

config = configparser.ConfigParser(allow_no_value = True)
config.read('./config.txt')

# if you dont have prisma cloud credentials, just use trivy, grype or another scanner
PRISMA_URI = config["PrismaCloud"]["URI"]
PRISMA_KEY = config["PrismaCloud"]["AccessKey"]
PRISMA_SEC = config["PrismaCloud"]["Secret"]

# TODO: der epos dude, interview?
# <https://teams.microsoft.com/l/message/19:WG0O_NCxEsOwPI39mYBssH8y-zmYFYeBWIOyaefkLCg1@thread.tacv2/1690191682241?tenantId=9744600e-3e04-492e-baa1-25ec245c6f10&amp;groupId=806c092e-2cc4-446a-ad2f-61c0b53907a4&amp;parentMessageId=1689836447011&amp;teamName=Security Champions Network&amp;channelName=General&amp;createdTime=1690191682241&amp;allowXTenantAccess=false>

"""
All base images relevant to the thesis
"""
BASE_IMAGES = [
    'node:14-slim', # DEPRECATED but still in use...
    'node:16-slim',
    'node:18-slim',
    # 'node:20',
    'node:20-slim',

    'php:latest',
    # 'php:fpm',
    # 'php:8.2-cli',
    'php:fpm-buster', # relevant!

    # From docker hub: This image is officially deprecated and all users are recommended to find and use suitable replacements ASAP. Some examples of other Official Image alternatives (listed in alphabetical order with no intentional or implied preference)
    # 'openjdk:11',
    # 'openjdk:11-slim-buster',
    # 'openjdk:17',
    # 'openjdk:17-slim-buster',
    # so for java we use some other ones:
    'ibmjava:jre',
    'registry.access.redhat.com/ubi9/openjdk-11-runtime',
    'registry.access.redhat.com/ubi9/openjdk-17-runtime',

    'amazonlinux:2',

    'alpine:latest',
    'node:18.14.1-alpine',
    'node:20-alpine', # -> TODO: check diff to alpine:latest. only node related issues?
    # java alpine? https://stackoverflow.com/questions/60014845/how-to-install-oracle-jdk11-in-alpine-linux-docker-image
    # -> no, bc we test alpine already

    # all relevant google distroless images
    'gcr.io/distroless/static-debian12',
    'gcr.io/distroless/base-debian12',
    # 'gcr.io/distroless/cc-debian12',
    'gcr.io/distroless/python3-debian12',
    'gcr.io/distroless/java-base-debian12',
    'gcr.io/distroless/java11-debian11',
    'gcr.io/distroless/java17-debian12',
    # 'gcr.io/distroless/nodejs16-debian11', # deprecated
    'gcr.io/distroless/nodejs18-debian12',
    'gcr.io/distroless/nodejs20-debian12',
    # we use ONE of the google distroless forked PHP images
    'piotrkardasz/php-distroless:8.1-nonroot-amd64-debian11',

    # all relevant "Ubuntu chisel" images (some of them *manually built locally* before running this script! cloned to ~/chisel: https://github.com/valentincanonical/chisel/blob/examples/examples/chiselled-base.dockerfile)
    # They have no explicit nodejs & python support as of sep 2023
    # 'ubuntu/dotnet-runtime',
    'ubuntu/jre:17-22.04_edge',
    'ubuntu/jre:8-22.04_edge',
    'chiselled-base:22.04', # base image - self built like described here https://github.com/valentincanonical/chisel/blob/examples/examples/chiselled-base.dockerfile see chisel and chisseled_base in Dockerfiles/

    # Redhat UBI micro
    'registry.access.redhat.com/ubi8/ubi-micro', # base image
    'registry.access.redhat.com/ubi8/ubi-minimal', # could be used for python

    # Redhat images "minimal" (not relevant!)
    # 'registry.access.redhat.com/ubi8/nodejs-18-minimal',
    # 'registry.access.redhat.com/ubi8/nodejs-20-minimal:latest', not available (yet)

    # Chainguard / wolfi
    'cgr.dev/chainguard/wolfi-base',
    'cgr.dev/chainguard/node:latest',
    'cgr.dev/chainguard/jre:latest',
    'cgr.dev/chainguard/php:latest',
    'cgr.dev/chainguard/python:latest',
    # not interesting for thesis
    # 'cgr.dev/chainguard/go:latest',
    # 'cgr.dev/chainguard/ruby:latest',

]

# tests:
# BASE_IMAGES = [
# 'cgr.dev/chainguard/wolfi-base',

# ]

def main():
    execute_command("rm -rf /src/results/twistcli/*.json")
    execute_command("rm -rf /src/Dockerfiles/*.dockerfile")

    for baseImage in BASE_IMAGES:
        baseImageNormalized = baseImage.replace("/", "-").replace(":", "_")
        # 1. scan using twistcli (evtl auch trivy)
        # generate dockerfiles and build test images first
        d = { 'baseImage': baseImage }
        content = """
FROM {baseImage}
CMD echo "Hello world"
""".format(**d)
        print ("\n=====> Using image " + baseImage)

        dockerFilePath = '/src/Dockerfiles/' + baseImageNormalized + '.dockerfile'
        writeFile(dockerFilePath, content)

        cmd = 'sudo docker build --quiet -t ' + baseImageNormalized + ' -f ' + dockerFilePath + ' /src/Dockerfiles'
        print(cmd)
        result = subprocess.check_output(cmd, shell=True)
        #print(result, "\n")

        # Scan:
        twistCliFilepath = '/src/results/twistcli/' + baseImageNormalized + '.json'
        cmd = 'sudo /usr/bin/twistcli images scan --output-file ' + twistCliFilepath + ' --address '+PRISMA_URI+' --publish=false -u '+ PRISMA_KEY + '-p '+ PRISMA_SEC + ' ' +  baseImageNormalized
        print(cmd)

        try:
            result = subprocess.check_output(cmd, shell=True, timeout=100000)
            print(result, "\n")
        except:
            print(result, "\n")

        # 2. anylse CVEs, exploits etc!

        # 3. read in json files and generate tables and charts!
        data = readTwistcliFile(twistCliFilepath)
        print("DATA FOR base image: " + baseImage)
        prettyPrint(data["vulnerabilityDistribution"])

        # for vul in data["vulns"]:
        #     prettyPrint(vul) # id, severity, packageName, packageVersion, link, riskFactors!, publishedDate, discoveredDate, impactedVersions
        #     die("OOOOOOOOOOO")
        print("\n ======================================================= \n")

        # TODO: generate csv oder so? hmm ne, einfach hier direkt mit den daten arbeiten!??!

        # 4 calculate statistics (media, T-test whatever!)

    writeFile("results/BASIC.json", json.dumps(plotData))
    # writeChartImage(plotData)
    die("done")


# Run the script
if __name__ == '__main__':
    main()
