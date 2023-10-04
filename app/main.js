const express = require("express");
const path = require("path");
const bodyParser = require("body-parser");
const execSync = require("child_process").execSync;
const app = express();
app.use(bodyParser.json());

app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "/index.html"));
});

app.post("/check", (req, res) => {
  const cve = req.params.cve;
  // TODO: ATTANTION, user input into system command
  const baseImage = req.params.baseImage;

  //TODO: optional. first use cve alone
  if (baseImage) {
    CMD = `/usr/local/bin/grype -o json ${baseImage} > /tmp/scan_results.json`;
    code = execSync(CMD);
    console.log("code ", code);

    const results = require("/tmp/scan_results.json");
    const hasZeroFindings = results.matches.length === 0;

    JSON.stringify(results);
  }

  console.log(
    "fetching ",
    `https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=${cve}`
  );

  fetch(
    `https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=${cve}`,
    //`https://cve.circl.lu/api/cve/${cve}`,

    {
      method: "GET",
      headers: {
        // https://nvd.nist.gov/developers/request-an-api-key
        apiKey: "11b20c32-c8ea-4ef7-b74b-48094a8a750b",
        Accept: "application/json",
        "Content-Type": "application/json",
      },
    }
  )
    .then((response) => {
      if (response.ok) {
        console.log("OK!!!!!!!!!!!!!!!!!!!!");

        response.json().then((json) => {
          console.log("YYYYYYYYYYYYYYYYYYYYYY", json);

          res.json({
            cveInfo: response,
          });
        });
      } else {
        res.json({
          cveInfo: "NONE",
        });
      }
    })

    .catch(function (err) {
      console.log("Unable to fetch -", err);
    });
});

app.listen(8000, () => {
  console.log("Listening...");
});
