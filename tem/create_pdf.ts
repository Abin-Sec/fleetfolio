import { jsPDF } from "https://esm.sh/jspdf@2.5.1";
import autoTable from "https://esm.sh/jspdf-autotable@3.5.29";


const [input] = Deno.args;
const payload = JSON.parse(input);

const tenant = payload.tenant || "UnknownTenant";
const session = payload.session || "UnknownSession";

const doc = new jsPDF();

const pageWidth = doc.internal.pageSize.getWidth();
const pageHeight = doc.internal.pageSize.getHeight();

const margin = { top: 15, bottom: 15, left: 15, right: 15 };
const contentWidth = pageWidth - margin.left - margin.right;

let y = margin.top;

/* ---------- COVER PAGE ---------- */

const logo = await loadImageAsBase64(
  "https://raw.githubusercontent.com/opsfolio/assets-public/refs/heads/main/opsfolio-branding/sub-brands/surveilr-patterns/logos/fleetfolio/fleetfolio-logo-primary.png"
);

doc.addImage(logo, "PNG", 140, 20, 40, 10);

doc.setFontSize(20);
doc.setTextColor(230, 140, 0);
doc.text(`${tenant} Penetration Testing Report`, pageWidth / 2, 140, {
  align: "center",
});

doc.addPage();
y = margin.top;
doc.setFont("helvetica", "bold");
doc.setTextColor(0, 0, 0);
doc.text("Document History", 10, 20);
const newDate = new Date().toISOString().slice(0, 10);

// ---- DOCUMENT HISTORY TABLE ----
autoTable(doc, {
  startY: 40,
  head: [[ "Version", "Date", "Author", "Comments" ]],
  body: [
    ["1.0", newDate, "", "Initial Version"]
  ],

  styles: {
    font: "helvetica",
    fontSize: 10,
    halign: "center",
    valign: "middle",
    lineWidth: 0.5,
    lineColor: [0, 102, 204],
    textColor: [0, 51, 102],
  },

  headStyles: {
    fontStyle: "bold",
    fillColor: [255, 255, 255],
    textColor: [0, 51, 102],
    lineWidth: 0.7,
    lineColor: [0, 102, 204],
  },

  bodyStyles: {
    fillColor: [135, 206, 235], // light blue row
  },

  columnStyles: {
    0: { cellWidth: 25 },
    1: { cellWidth: 35 },
    2: { cellWidth: 60 },
    3: { cellWidth: 50 },
  },
});

// move cursor below table
y = (doc as any).lastAutoTable.finalY + 10;

// Continue with next page
doc.addPage();
y = margin.top;
y = margin.top;

doc.setFont("helvetica", "bold");
doc.setFontSize(16);
doc.setTextColor(0, 0, 0);
doc.text("Criteria for Risk Ratings", margin.left, y);

y += 8;

// Intro text
doc.setFont("helvetica", "normal");
doc.setFontSize(11);
doc.text(
  "The Table below outlines the general rules for assigning risk ratings for identified vulnerabilities:",
  margin.left,
  y
);

y += 10;

// Draw table
drawRiskCriteriaTable();



/* ---------- HELPERS ---------- */

function sanitizeFileName(text: string) {
  return text.replace(/[^a-zA-Z0-9-_]/g, "_");
}

async function loadImageAsBase64(url: string) {
  const res = await fetch(url);
  const blob = await res.arrayBuffer();

  const base64 = btoa(
    new Uint8Array(blob).reduce(
      (data, byte) => data + String.fromCharCode(byte),
      ""
    )
  );

  return `data:image/png;base64,${base64}`;
}

function writeText(text: string, fontSize = 11, bold = false,color = false) {
  doc.setFont("helvetica", bold ? "bold" : "normal");
  doc.setFontSize(fontSize);
  if(color)
    doc.setTextColor(0, 120, 255);
  else
    doc.setTextColor(0, 0, 0);

  const lines = doc.splitTextToSize(text || "-", contentWidth);

  if (y + lines.length * 5 > pageHeight - margin.bottom) {
    doc.addPage();
    y = margin.top;
  }

  doc.text(lines, margin.left, y);
  y += lines.length * 5 + 4;
}

/* ---------- NUMBER TO WORDS ---------- */

function numberToWords(n: number): string {
  const words = [
    "Zero","One","Two","Three","Four","Five",
    "Six","Seven","Eight","Nine","Ten",
    "Eleven","Twelve","Thirteen","Fourteen","Fifteen",
    "Sixteen","Seventeen","Eighteen","Nineteen","Twenty"
  ];

  if (n >= 0 && n < words.length) return words[n];
  return n.toString(); // fallback for large numbers
}


/* ---------- SEVERITY STYLE ---------- */

function getSeverityStyle(level: string) {
  switch ((level || "").toLowerCase()) {
    case "critical":
      return { bg: [200, 0, 0], text: [0, 0, 0] };
    case "high":
      return { bg: [255, 80, 0], text: [0, 0, 0] };
    case "medium":
      return { bg: [255, 200, 0], text: [0, 0, 0] };
    case "low":
      return { bg: [0, 120, 255], text: [0, 0, 0] };
    default:
      return { bg: [150, 150, 150], text: [0, 0, 0] };
  }
}

/* ---------- STATUS STYLE (FIXED) ---------- */

function getStatusStyle(status: string) {
  switch ((status || "").toLowerCase().trim()) {
    case "remediated":
      return { bg: [0, 160, 80], text: [0, 0, 0] }; // green
    case "inprogress":
      return { bg: [255, 165, 0], text: [0, 0, 0] }; // orange
    case "not remediated":
      return { bg: [180, 180, 180], text: [0, 0, 0] }; // grey
    default:
      return { bg: [150, 150, 150], text: [0, 0, 0] };
  }
}

/* ---------- BADGES ---------- */

function drawSeverityBadge(level: string) {
  const style = getSeverityStyle(level);
  const label = "Risk Rating : ";
  doc.setFont("helvetica", "bold");
  doc.setTextColor(0, 0, 0);
  doc.text(label, margin.left, y);

  let x = margin.left + doc.getTextWidth(label);

  const badgeText = (level || "-").toUpperCase();
  const padding = 2;

  const textWidth = doc.getTextWidth(badgeText);
  const badgeWidth = textWidth + padding * 2;
  doc.setFillColor(...style.bg);
  doc.roundedRect(x, y - 4, badgeWidth, 6, 2, 2, "F");

  doc.setTextColor(...style.text);
  doc.text(badgeText, x + padding, y);

  y += 8;
}

function drawStatusBadge(status: string,level:string) {
  let style ={}
  if(status.toLowerCase()=='remediated'){
    style = getStatusStyle(status);
  }
  else{
    style = getSeverityStyle(level);
  }
  const label = "Status : ";
  doc.setFont("helvetica", "bold");
  doc.setTextColor(0, 0, 0);

  doc.text(label, margin.left, y);

  let x = margin.left + doc.getTextWidth(label);

  const badgeText = status.toUpperCase();
  const padding = 2;

  doc.setFont("helvetica", "bold");

  const textWidth = doc.getTextWidth(badgeText);
  const badgeWidth = textWidth + padding * 2;
  const badgeHeight = 6;
  doc.setFillColor(...style.bg);
  doc.roundedRect(x, y - 4, badgeWidth, badgeHeight, 2, 2, "F");
  doc.setTextColor(...style.text);
  doc.text(badgeText, x + padding, y);

  y += 8;
}

/* ---------- SEVERITY MESSAGE ---------- */

function writeSeverityMessage(level: string, count: number) {
  const countText = count === 0 ? "No" : numberToWords(count);
  const suffix = " severity issues were found in the application.";

  let x = margin.left;
  doc.setFontSize(11);

  doc.setTextColor(0, 0, 0);
  doc.text(`${countText} `, x, y);
  x += doc.getTextWidth(`${countText} `);

  doc.setTextColor(...getSeverityStyle(level).bg);
  doc.text(level, x, y);
  x += doc.getTextWidth(level);

  doc.setTextColor(0, 0, 0);
  doc.text(suffix, x, y);

  y += 6;
}

/* ---------- GROUP BY SEVERITY ---------- */

const severityOrder = ["Critical", "High", "Medium", "Low"];

const grouped: Record<string, any[]> = {
  Critical: [],
  High: [],
  Medium: [],
  Low: [],
};

(payload.interp || []).forEach((task: any) => {
  const p = (task.priority || "").toLowerCase();
  if (p.includes("critical")) grouped.Critical.push(task);
  else if (p.includes("high")) grouped.High.push(task);
  else if (p.includes("medium")) grouped.Medium.push(task);
  else grouped.Low.push(task);
});

/* ---------- PREFIX ---------- */

function getPrefix(level: string, index: number) {
  const map: any = { Critical: "C", High: "H", Medium: "M", Low: "L" };
  return `${map[level]}${index + 1}`;
}

/* ---------- WRITE FINDINGS ---------- */

severityOrder.forEach((level) => {
  writeText(`${level} Risk Findings`, 16, true,false);
  writeSeverityMessage(level, grouped[level].length);

  grouped[level].forEach((task: any, idx: number) => {
    y += 6;

    writeText(`${getPrefix(level, idx)}. ${task.title}`, 14, true,true);
    drawSeverityBadge(task.priority);
    drawStatusBadge(task?.status?.replace('_',' '),task.priority);

    y += 4;

    writeText("Summary", 12, true,false);
    writeText(task.description);

    writeText("Parameter Affected", 12, true,false);
    writeText(task.parameter_affected.replace('```',''));

    writeText("Steps Reproduced", 12, true,false);
    writeText(task.steps_reproduced);

    writeText("Business Impact", 12, true,false);
    writeText(task.bussiness_impact);

    writeText("Recommendation", 12, true,false);
    writeText(task.recommentation);

    writeText("Reference", 12, true,false);
    writeText(task.reference);

    y += 8;
  });
});

/*-------------Risk Rating -------------*/
function drawRiskCriteriaTable() {
  const startX = margin.left;
  let startY = y;

  const col1Width = 40;
  const col2Width = contentWidth - col1Width;
  const rowPadding = 4;

  const rows = [
    {
      label: "CRITICAL",
      color: [200, 0, 0],
      textColor: [0, 0, 0],
      desc:
        "These issues can allow attackers to execute code on the web application or application server, or access sensitive data. Examples of High-Risk issues include SQL injections, remote code execution, command injection.",
    },
    {
      label: "HIGH",
      color: [255, 0, 0],
      textColor: [0, 0, 0],
      desc:
        "These issues will allow malicious attackers to access application resources and data. This can allow an attacker to steal session information or sensitive data from the application or server. Examples include known XFI, XSS, buffer overflows, unauthorized access and disclosure of sensitive information.",
    },
    {
      label: "MEDIUM",
      color: [255, 200, 0],
      textColor: [0, 0, 0],
      desc:
        "These issues identify conditions that do not immediately or directly result in compromise of a network, system, application or information, but do provide information that could be used in combination with other information to gain insight into how to compromise or gain unauthorized access.",
    },
    {
      label: "LOW",
      color: [0, 160, 220],
      textColor: [0, 0, 0],
      desc:
        "Vulnerabilities in the low range typically have very little impact on an organization's business. Exploitation of such vulnerabilities usually requires local or physical system access.",
    },
    {
      label: "INFO",
      color: [180, 180, 180],
      textColor: [0, 0, 0],
      desc:
        "An informational severity level typically indicates findings that do not directly impact the security of the application but provide useful information.",
    },
    {
      label: "REMEDIATED",
      color: [0, 160, 80],
      textColor: [0, 0, 0],
      desc:
        "The issue has been fixed since the previous round of penetration testing.",
    },
    {
      label: "NOT REMEDIATED",
      color: [255, 255, 255],
      textColor: [0, 0, 0],
      desc:
        "The issue has not been fixed.",
    },
  ];

  rows.forEach((row) => {
    const descLines = doc.splitTextToSize(row.desc, col2Width - rowPadding * 2);
    const rowHeight = descLines.length * 5 + rowPadding * 2;

    // Page break check
    if (startY + rowHeight > pageHeight - margin.bottom) {
      doc.addPage();
      startY = margin.top;
    }

    // Left colored cell
    doc.setFillColor(...row.color);
    doc.rect(startX, startY, col1Width, rowHeight, "F");

    doc.setTextColor(...row.textColor);
    doc.setFont("helvetica", "bold");
    doc.text(
      row.label,
      startX + col1Width / 2,
      startY + rowHeight / 2 + 2,
      { align: "center" }
    );

    // Right description cell
    doc.setDrawColor(0);
    doc.rect(startX + col1Width, startY, col2Width, rowHeight);

    doc.setFont("helvetica", "normal");
    doc.setTextColor(0, 0, 0);
    doc.text(
      descLines,
      startX + col1Width + rowPadding,
      startY + rowPadding + 4
    );

    // Border around entire row
    doc.rect(startX, startY, col1Width + col2Width, rowHeight);

    startY += rowHeight;
  });

  y = startY + 10;
}


/* ---------- PAGE NUMBERS ---------- */

const pageCount = doc.getNumberOfPages();

for (let i = 1; i <= pageCount; i++) {
  doc.setPage(i);
  doc.setFontSize(8);
  doc.setFont("helvetica", "normal");
  doc.text(`${i}`, pageWidth - margin.right, pageHeight - 5, { align: "right" });
  doc.text(`${tenant.toUpperCase()}` + ' PENETRATION TEST REPORT', margin.left, pageHeight - 5);
}

/* ---------- EXPORT (SAFE BASE64) ---------- */

const fileName = `${sanitizeFileName(tenant)}_${sanitizeFileName(
  session
)}_pentest_report.pdf`;

const arrayBuffer = doc.output("arraybuffer");
const uint8 = new Uint8Array(arrayBuffer);

// Safe conversion without spread operator
let binary = "";
const chunkSize = 0x8000; // 32KB chunks

for (let i = 0; i < uint8.length; i += chunkSize) {
  binary += String.fromCharCode(
    ...uint8.subarray(i, i + chunkSize)
  );
}

const base64 = btoa(binary);

await Deno.stdout.write(
  new TextEncoder().encode(
    `data:application/pdf;name=${fileName};base64,${base64}`
  )
);
