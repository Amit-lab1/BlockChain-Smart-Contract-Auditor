import jsPDF from "jspdf";
import autoTable from "jspdf-autotable";
import { useState } from "react";
import axios from "axios";
import {
  PieChart,
  Pie,
  Cell,
  Tooltip,
  ResponsiveContainer
} from "recharts";

const COLORS = ["#ef4444", "#f97316", "#eab308", "#22c55e"];

function App() {

const [findings, setFindings] = useState([]);
const [selectedFile, setSelectedFile] = useState(null);

const severityCounts = {
  Critical: findings.filter(f => f.severity === "Critical").length,
  High: findings.filter(f => f.severity === "High").length,
  Medium: findings.filter(f => f.severity === "Medium").length,
  Low: findings.filter(f => f.severity === "Low").length,
};

const severityData = [
  { name: "Critical", value: severityCounts.Critical },
  { name: "High", value: severityCounts.High },
  { name: "Medium", value: severityCounts.Medium },
  { name: "Low", value: severityCounts.Low },
];

const detectionCounts = {
  Static: 0,
  Dynamic: 0,
  Symbolic: 0,
  Taint: 0,
  Fuzz: 0,
};

findings.forEach((finding) => {

  const methods = finding.detection_method.split("+");

  methods.forEach((method) => {

    const trimmed = method.trim();

    if (trimmed.includes("Static")) {
      detectionCounts.Static++;
    }

    if (trimmed.includes("Dynamic")) {
      detectionCounts.Dynamic++;
    }

    if (trimmed.includes("Symbolic")) {
      detectionCounts.Symbolic++;
    }

    if (trimmed.includes("Taint")) {
      detectionCounts.Taint++;
    }

    if (trimmed.includes("Fuzz")) {
      detectionCounts.Fuzz++;
    }

  });

});

const detectionData = [
  { name: "Static", value: detectionCounts.Static },
  { name: "Dynamic", value: detectionCounts.Dynamic },
  { name: "Symbolic", value: detectionCounts.Symbolic },
  { name: "Taint", value: detectionCounts.Taint },
  { name: "Fuzz", value: detectionCounts.Fuzz },
];

const downloadReport = () => {

  const doc = new jsPDF();

  // Title
  doc.setFontSize(22);
  doc.text("BlockSentinel AI Audit Report", 20, 20);

  // Metadata
  doc.setFontSize(12);

  doc.text(
    `Generated: ${new Date().toLocaleString()}`,
    20,
    35
  );

  const securityScore =
    Math.max(
      100 -
      (
        severityCounts.Critical * 25 +
        severityCounts.High * 15 +
        severityCounts.Medium * 8 +
        severityCounts.Low * 3
      ),
      0
    );

  doc.text(
    `Security Score: ${securityScore}/100`,
    20,
    45
  );

  doc.text(
    `Total Vulnerabilities: ${findings.length}`,
    20,
    55
  );

  // Severity Breakdown
  doc.text(
    `Critical: ${severityCounts.Critical}`,
    20,
    70
  );

  doc.text(
    `High: ${severityCounts.High}`,
    20,
    80
  );

  doc.text(
    `Medium: ${severityCounts.Medium}`,
    20,
    90
  );

  doc.text(
    `Low: ${severityCounts.Low}`,
    20,
    100
  );

  // Findings Table
  autoTable(doc, {

    startY: 115,

    head: [[
      "Vulnerability",
      "Severity",
      "Risk",
      "Line",
      "Detection",
      "Recommendation"
    ]],

    body: findings.map((finding) => [

      finding.vulnerability,
      finding.severity,
      finding.risk_score,
      finding.line,
      finding.detection_method,
      finding.recommendation

    ]),

    styles: {
      fontSize: 8
    },

    headStyles: {
      fillColor: [0, 255, 255]
    }

  });

  // Save PDF
  doc.save("BlockSentinel_Audit_Report.pdf");

};

const handleFileUpload = async (event) => {
  
    const file = selectedFile;

    if (!file) {
      alert("Please select a Solidity file");
      return;
    }

    const formData = new FormData();

    formData.append("file", file);

    try {

      const response = await axios.post(
        "http://127.0.0.1:5000/upload",
        formData,
        {
          headers: {
            "Content-Type": "multipart/form-data",
          },
        }
      );

      alert(response.data.message);

      console.log(response.data);
      setFindings(response.data.findings);

    } catch (error) {

      console.error(error);

      alert("Upload failed");

    }
  };
  return (
    <div className="min-h-screen bg-slate-950 text-white">

      {/* Navbar */}
      <nav className="flex items-center justify-between px-10 py-5 border-b border-slate-800 bg-slate-900">

        <div>
          <h1 className="text-3xl font-bold text-cyan-400">
            BlockSentinel AI
          </h1>

          <p className="text-slate-400 text-sm">
            Smart Contract Security Auditor
          </p>
        </div>

        <button className="bg-cyan-500 hover:bg-cyan-600 px-5 py-2 rounded-xl font-semibold transition">
          Start Scan
        </button>

      </nav>

      {/* Main Content */}
      <div className="p-10">

        {/* Header */}
        <div className="mb-10">
          <h2 className="text-5xl font-bold text-white">
            Security Dashboard
          </h2>

          <p className="mt-3 text-slate-400 text-lg">
            Hybrid AI-powered blockchain smart contract vulnerability detection platform
          </p>
        </div>

        {/* Severity Cards */}
        <div className="grid grid-cols-4 gap-6 mb-10">

          <div className="bg-slate-900 p-6 rounded-2xl border border-red-500">
            <h2 className="text-xl font-semibold text-red-400">
              Critical
            </h2>

            <p className="text-5xl mt-5 font-bold">
              {severityCounts.Critical}
            </p>
          </div>

          <div className="bg-slate-900 p-6 rounded-2xl border border-orange-500">
            <h2 className="text-xl font-semibold text-orange-400">
              High
            </h2>

            <p className="text-5xl mt-5 font-bold">
              {severityCounts.High}
            </p>
          </div>

          <div className="bg-slate-900 p-6 rounded-2xl border border-yellow-500">
            <h2 className="text-xl font-semibold text-yellow-400">
              Medium
            </h2>

            <p className="text-5xl mt-5 font-bold">
              {severityCounts.Medium}
            </p>
          </div>

          <div className="bg-slate-900 p-6 rounded-2xl border border-green-500">
            <h2 className="text-xl font-semibold text-green-400">
              Low
            </h2>

            <p className="text-5xl mt-5 font-bold">
                {severityCounts.Low}

            </p>
          </div>

        </div>

        {/* Upload Section */}
<div className="bg-slate-900 border border-slate-800 rounded-2xl p-8 mb-10">

  <h2 className="text-3xl font-bold mb-4 text-cyan-400">
    Upload Smart Contract
  </h2>

  <p className="text-slate-400 mb-6">
    Upload Solidity (.sol) smart contracts for hybrid AI-powered vulnerability analysis.
  </p>

  <div className="flex items-center gap-4">

    <input
      type="file"
      accept=".sol"
      onChange={(event) => setSelectedFile(event.target.files[0])}
      className="bg-slate-800 text-white p-3 rounded-xl border border-slate-700 w-full"
   />

    <button
      onClick={handleFileUpload}
      className="bg-cyan-500 hover:bg-cyan-600 px-6 py-3 rounded-xl font-semibold transition"
    >
     Scan Contract
    </button>

    <button
      onClick={downloadReport}
      className="bg-green-500 hover:bg-green-600 px-6 py-3 rounded-xl font-semibold transition"
    >
      Download Report
    </button>

  </div>

</div>

        {/* Dashboard Grid */}
        <div className="grid grid-cols-3 gap-8">

          {/* Pie Chart */}
          <div className="bg-slate-900 rounded-2xl p-6 border border-slate-800">

            <h2 className="text-2xl font-bold mb-6">
              Vulnerability Severity Distribution
            </h2>

            <div className="h-80">

              <ResponsiveContainer width="100%" height="100%">
                <PieChart>

                  <Pie
                    data={severityData}
                    dataKey="value"
                    nameKey="name"
                    outerRadius={120}
                    label
                  >
                    {severityData.map((entry, index) => (
                      <Cell
                        key={`cell-${index}`}
                        fill={COLORS[index % COLORS.length]}
                      />
                    ))}
                  </Pie>

                  <Tooltip />

                </PieChart>
              </ResponsiveContainer>

            </div>

          </div>

          {/* Security Score */}
          <div className="bg-slate-900 rounded-2xl p-6 border border-slate-800">

            <h2 className="text-2xl font-bold mb-6">
              Security Score
            </h2>

            <div className="flex flex-col items-center justify-center h-80">

              <div className="w-48 h-48 rounded-full border-[12px] border-cyan-500 flex items-center justify-center">

                <div className="text-center">
                  <h1 className="text-5xl font-bold text-cyan-400">
                    {
  Math.max(
    100 -
    (
      severityCounts.Critical * 25 +
      severityCounts.High * 15 +
      severityCounts.Medium * 8 +
      severityCounts.Low * 3
    ),
    0
  )
}
                  </h1>

                  <p className="text-slate-400 mt-2">
                    / 100
                  </p>
                </div>

              </div>

              <p className="mt-6 text-slate-400 text-lg">
                Moderate Security Risk Detected
              </p>

            </div>

          </div>

          {/* Detection Methods */}
<div className="bg-slate-900 rounded-2xl p-6 border border-slate-800">

  <h2 className="text-2xl font-bold mb-6">
    Detection Methods
  </h2>

  <div className="space-y-5">

    {/* Static */}
    <div>

      <div className="flex justify-between mb-1">
        <span>Static Analysis</span>
        <span>{detectionCounts.Static}</span>
      </div>

      <div className="w-full bg-slate-800 rounded-full h-3">

        <div
          className="bg-cyan-500 h-3 rounded-full"
          style={{
            width: `${Math.min(detectionCounts.Static * 20, 100)}%`
          }}
        ></div>

      </div>

    </div>

    {/* Dynamic */}
    <div>

      <div className="flex justify-between mb-1">
        <span>Dynamic Analysis</span>
        <span>{detectionCounts.Dynamic}</span>
      </div>

      <div className="w-full bg-slate-800 rounded-full h-3">

        <div
          className="bg-orange-500 h-3 rounded-full"
          style={{
            width: `${Math.min(detectionCounts.Dynamic * 20, 100)}%`
          }}
        ></div>

      </div>

    </div>

    {/* Symbolic */}
    <div>

      <div className="flex justify-between mb-1">
        <span>Symbolic Execution</span>
        <span>{detectionCounts.Symbolic}</span>
      </div>

      <div className="w-full bg-slate-800 rounded-full h-3">

        <div
          className="bg-purple-500 h-3 rounded-full"
          style={{
            width: `${Math.min(detectionCounts.Symbolic * 20, 100)}%`
          }}
        ></div>

      </div>

    </div>

    {/* Taint */}
    <div>

      <div className="flex justify-between mb-1">
        <span>Taint Analysis</span>
        <span>{detectionCounts.Taint}</span>
      </div>

      <div className="w-full bg-slate-800 rounded-full h-3">

        <div
          className="bg-red-500 h-3 rounded-full"
          style={{
            width: `${Math.min(detectionCounts.Taint * 20, 100)}%`
          }}
        ></div>

      </div>

    </div>

    {/* Fuzz */}
    <div>

      <div className="flex justify-between mb-1">
        <span>Fuzz Testing</span>
        <span>{detectionCounts.Fuzz}</span>
      </div>

      <div className="w-full bg-slate-800 rounded-full h-3">

        <div
          className="bg-green-500 h-3 rounded-full"
          style={{
            width: `${Math.min(detectionCounts.Fuzz * 20, 100)}%`
          }}
        ></div>

      </div>

    </div>

  </div>

</div>

        </div>

        {/* Vulnerability Findings */}
<div className="mt-10 bg-slate-900 rounded-2xl p-6 border border-slate-800">

  <h2 className="text-3xl font-bold mb-6 text-cyan-400">
    Vulnerability Findings
  </h2>

  {findings.length === 0 ? (

    <p className="text-slate-400">
      No vulnerabilities scanned yet.
    </p>

  ) : (

    <div className="overflow-x-auto">

      <table className="w-full border-collapse">

        <thead>

          <tr className="bg-slate-800">

            <th className="p-4 text-left">Vulnerability</th>
            <th className="p-4 text-left">Severity</th>
            <th className="p-4 text-left">Risk Score</th>
            <th className="p-4 text-left">Line</th>
            <th className="p-4 text-left">Detection Method</th>
            <th className="p-4 text-left">Recommendation</th>
            <th className="p-4 text-left">AI Analysis</th>

          </tr>

        </thead>

        <tbody>

          {findings.map((finding, index) => (

            <tr
              key={index}
              className="border-b border-slate-800 hover:bg-slate-800 transition"
            >

              <td className="p-4">
                {finding.vulnerability}
              </td>

              <td className="p-4">

                <span
                  className={`px-3 py-1 rounded-full text-sm font-semibold
                  ${
                    finding.severity === "Critical"
                      ? "bg-red-500/20 text-red-400"
                      : finding.severity === "High"
                      ? "bg-orange-500/20 text-orange-400"
                      : finding.severity === "Medium"
                      ? "bg-yellow-500/20 text-yellow-400"
                      : "bg-green-500/20 text-green-400"
                  }`}
               >
                  {finding.severity}
               </span>

              </td>

              <td className="p-4">
                {finding.risk_score}
              </td>

              <td className="p-4">
                {finding.line}
              </td>

              <td className="p-4">
                {finding.detection_method}
              </td>

              <td className="p-4 text-slate-300">
                {finding.recommendation}
              </td>

              <td className="p-4 text-slate-400 max-w-md">
                {finding.ai_analysis}
              </td>

            </tr>

          ))}

        </tbody>

      </table>

    </div>

  )}

</div>

      </div>

    </div>
  );
}

export default App;