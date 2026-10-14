import subprocess
import json
import os
import re

from flask import Flask, request, jsonify
from flask_cors import CORS

app = Flask(__name__)

# Enable CORS
CORS(app)

# Upload folder
UPLOAD_FOLDER = "uploads"

os.makedirs(
    UPLOAD_FOLDER,
    exist_ok=True
)

# Home route
@app.route("/")
def home():

    return {
        "message":
            "BlockSentinel AI Backend Running Successfully"
    }

# Upload smart contract
@app.route("/upload", methods=["POST"])
def upload_contract():

    try:

        # Check file exists
        if "file" not in request.files:

            return jsonify({
                "error":
                    "No file uploaded"
            }), 400

        file = request.files["file"]

        # Empty filename check
        if file.filename == "":

            return jsonify({
                "error":
                    "Empty filename"
            }), 400

        # Allow only Solidity files
        if not file.filename.endswith(".sol"):

            return jsonify({
                "error":
                    "Only .sol files are allowed"
            }), 400

        # Save uploaded file
        filepath = os.path.join(
            UPLOAD_FOLDER,
            file.filename
        )

        file.save(filepath)

        # Read contract code
        with open(
            filepath,
            "r",
            encoding="utf-8"
        ) as contract_file:

            contract_code = contract_file.read()

        # Detect Solidity version
        version_match = re.search(
            r'pragma solidity\s+\^?([0-9]+\.[0-9]+\.[0-9]+)',
            contract_code
        )

        if version_match:

            solidity_version = version_match.group(1)

            try:

                subprocess.run(
                    [
                        "solc-select",
                        "use",
                        solidity_version
                    ],
                    check=True,
                    capture_output=True,
                    text=True
                )

                print(
                    f"Using Solidity compiler version: "
                    f"{solidity_version}"
                )

            except Exception as compiler_error:

                return jsonify({

                    "error":
                        f"Compiler version "
                        f"{solidity_version} "
                        f"not installed.",

                    "details":
                        str(compiler_error)

                }), 500

        findings = []

        # Run Slither analysis
        slither_command = [
            "slither",
            filepath,
            "--json",
            "-"
        ]

        result = subprocess.run(
            slither_command,
            capture_output=True,
            text=True
        )

        slither_output = result.stdout

        if slither_output:

            slither_data = json.loads(
                slither_output
            )

            detectors = slither_data.get(
                "results",
                {}
            ).get(
                "detectors",
                []
            )

            for detector in detectors:

                findings.append({

                    "vulnerability":
                        detector.get(
                            "check",
                            "Unknown"
                        ),

                    "severity":
                        detector.get(
                            "impact",
                            "Medium"
                        ),

                    "risk_score":
                        80,

                    "line":
                        detector.get(
                            "elements",
                            [{}]
                        )[0].get(
                            "source_mapping",
                            {}
                        ).get(
                            "lines",
                            ["N/A"]
                        )[0],

                    "detection_method":
                        "Static Analysis (Slither)",

                    "recommendation":
                        detector.get(
                            "description",
                            "Manual review required."
                        ),

                    "ai_analysis":
                        f"This smart contract contains a "
                        f"{detector.get('impact', 'Medium')} "
                        f"severity vulnerability called "
                        f"{detector.get('check', 'Unknown')}. "
                        f"This issue may introduce security risks "
                        f"and should be reviewed carefully "
                        f"by the developer."

                })

        # If no findings detected
        if len(findings) == 0:

            findings.append({

                "vulnerability":
                    "No Major Vulnerabilities Detected",

                "severity":
                    "Safe",

                "risk_score":
                    10,

                "line":
                    "N/A",

                "detection_method":
                    "Static Analysis (Slither)",

                "recommendation":
                    "No immediate action required.",

                "ai_analysis":
                    "The uploaded smart contract appears "
                    "to be relatively secure based on "
                    "current Slither analysis."

            })

        # Return results
        return jsonify({

            "message":
                "Smart contract scanned successfully",

            "filename":
                file.filename,

            "path":
                filepath,

            "total_vulnerabilities":
                len(findings),

            "findings":
                findings

        })

    except Exception as e:

        return jsonify({

            "error":
                "Smart contract analysis failed",

            "details":
                str(e)

        }), 500

# Run Flask server
if __name__ == "__main__":

    app.run(debug=True)