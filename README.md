# Distroless Evaluation

This is the source code related to my master thesis "Evaluating the security of software containers through reduction of potentially vulnerable components".

Read the paper [here](https://mwager.de/assets/component_reduction_paper.pdf).

More info at [mwager.de](https://mwager.de).


## Download

```
$ git clone https://github.com/mwager/distroless_evaluation.git
```

## Files & Folders

- `scan.py` - builds and scans all relevant base images which creates the JSON files containing the scanner results for later analysis
- `analysis.py` - analyses the JSON files generated by scan.py and adds additional info to each vulnerability (e.g. EPSS exploit probability). Writes `results/FINAL.json`
- `results.py` - reads `results/FINAL.json` generated before and generates statistics for the thesis
- `helpers.py` - implements common helper functions used by the other scripts
- `Dockerfiles/` This folder contains all (automatically created) Dockerfiles used to build the images which are scanned for evaluation
- `results/` This folder contains the generated files from the scanner twistcli with the scan results, to be parsed by python
- `app/` This folder contains all nodejs sources for the implemented webapp to support vulnerability assessments

## Vagrant setup

For all docker related tasks and running the vulnerability scans, a virtual machine using vagrant is used. The folder /src inside the machine is the synced folder (.)

```
# boot the virtual machine used for the evaluation
$ vagrant up

# ssh into the machine
$ vagrant ssh

# How to:
# -------
$ cd /src
# Execute the python files in this order:
$ python3 scan.py
$ python3 analysis.py
$ python3 results.py
```

### Remove all images:

```
$ sudo docker rmi -f $(sudo docker images -a -q)
```

### Downloading twistcli

For twistcli an accesskey and secret is needed.

```
- curl -k -u $ACCESS_KEY:$SECRET_KEY --output ./twistcli $PRISMA_ADDRESS/api/v1/util/twistcli
- chmod a+x ./twistcli
- # Now use it to scan an image like documented above
- ./twistcli images scan ...
```

### Scanning

twistcli:

```
$ sudo /usr/bin/twistcli images scan --output-file twistcli-results.json --details --address $ADDRESS --publish=false -u $ACCESSKEY -p $SECRET $IMAGE_NAME
```

Trivy:

```
$ sudo trivy image -f json -o trivy-results.json $IMAGE_NAME
```
