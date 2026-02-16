
/* ===============================
   CTRL + P → Trigger export
   ONLY when modal is visible
=================================*/
document.addEventListener("keydown", function (event) {

  const isPrintShortcut =
    (event.ctrlKey || event.metaKey) &&
    event.key.toLowerCase() === "p";

  if (!isPrintShortcut) return;

  const modal = document.getElementById("penetration_modal");

  const isModalOpen =
    modal &&
    (modal.classList.contains("show") || modal.offsetParent !== null);

  if (!isModalOpen) return;

  event.preventDefault();   
  silentPrint(modal.innerHTML);
});


/* ===============================
   SILENT PRINT FUNCTION
=================================*/
function silentPrint(htmlContent) {

  let iframe = document.getElementById("print-iframe");

  if (!iframe) {
    iframe = document.createElement("iframe");
    iframe.id = "print-iframe";
    iframe.style.position = "fixed";
    iframe.style.right = "0";
    iframe.style.bottom = "0";
    iframe.style.width = "0";
    iframe.style.height = "0";
    iframe.style.border = "0";
    iframe.style.visibility = "hidden";
    document.body.appendChild(iframe);
  }

  const doc = iframe.contentWindow.document;

  doc.open();
  doc.write(`
    <html>
      <head>
        <style>
          @page {
            size: A4;
            margin: 20mm;
          }
          html, body {
            margin: 0;
            padding: 0;
            font-family: Arial, sans-serif;
          }
        </style>
        <title></title>
      </head>
      <body>
        ${htmlContent}
      </body>
    </html>
  `);
  doc.close();

  iframe.onload = function () {
    iframe.contentWindow.focus();
    iframe.contentWindow.print();
  };
}
