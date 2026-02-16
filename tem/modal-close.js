
//-- Modal Save button event
document.addEventListener("submit", function (e) {
  const form = e.target;
  if (!(form instanceof HTMLFormElement)) return;
  e.preventDefault();
  const formData = new FormData(form);
  const tool = getParam("tool");
  const uid = getParam("uid");
  const priority = getParam("priority");
  const fixed = getParam("fixed");
  // Send POST manually to SQLPage action
  fetch(form.action, {
    method: form.method || "POST",
    body: formData
  })
  .then(() => {
    showToast("Interpretation Saved Successfully");
    
    setTimeout(() => {
      // Close modal
      window.dispatchEvent(new CustomEvent("sqlpage:modal:close"));
      let url;
      if (uid && !tool){
        url = `/threatmanagement/interpretations.sql?uid=${uid}`;
      }
      else if(tool && !priority && !fixed){
         url = `/tools/findings.sql?tool=${tool}`;
      }
      else if(priority){
         url = `/tools/findings.sql?priority=${priority}`;
      }
      else if(tool && fixed){
        url = `/tools/findings.sql?tool=${tool}&fixed=${fixed}`;
     }
      window.location.href = url;
    }, 100);
  
   
  })
  .catch(err => {
    console.error("❌ Save failed", err);
    alert("Save failed. Please try again.");
  });

}, true);

//-- Confirmation modal  button event
document.addEventListener("click", function (e) {

  const link = e.target.closest("a");
  if (!link) return;

  // Only catch delete button clicks
  if (!link.href.includes("/interpretation/delete.sql")) return;

  e.preventDefault();

  const tool = getParam("tool");
  const url = link.href;

  fetch(url, {
    method: "POST"
  })
  .then(res => {
    if (!res.ok) throw new Error("Delete failed");    
    showToast("Interpretation Deleted Successfully");
    setTimeout(() => {
      window.dispatchEvent(new CustomEvent("sqlpage:modal:close"));
      window.location.href = `/tools/findings.sql?tool=${tool}`;
    }, 1000);
  })
  .catch(err => {
    console.error("❌ Delete failed", err);
    alert("Delete failed. Please try again.");
  });

}, true);

function getParam(name) {
  const params = new URLSearchParams(window.location.search);
  return params.get(name);
}

function showToast(message) {
  // Create toast container if not exists
  let container = document.getElementById("toast-container");
  if (!container) {
    container = document.createElement("div");
    container.id = "toast-container";
    container.style.position = "fixed";
    container.style.bottom = "20px";
    container.style.right = "20px";
    container.style.zIndex = "9999";
    document.body.appendChild(container);
  }

  // Create toast element
  const toast = document.createElement("div");
  toast.className = "toast align-items-center text-bg-success show";
  toast.style.minWidth = "250px";
  toast.style.marginTop = "10px";

  toast.innerHTML = `
    <div class="d-flex">
      <div class="toast-body">
         ${message}
      </div>
      <button type="button" class="btn-close btn-close-white me-2 m-auto"></button>
    </div>
  `;

  container.appendChild(toast);

  // Auto remove after 2 seconds
  setTimeout(() => {
    toast.remove();
  }, 2000);
}
