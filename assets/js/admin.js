(function () {
 const dialog = document.getElementById("confirm-dialog");
 const form = document.getElementById("confirm-form");
 const text = document.getElementById("confirm-text");
 const submit = document.getElementById("confirm-submit");
 const cancel = document.getElementById("confirm-cancel");
 if (!dialog || !form || !cancel || !text || !submit) return;
 document.querySelectorAll("[data-delete-url]").forEach((button) => {
  button.addEventListener("click", () => {
   form.setAttribute("action", button.getAttribute("data-delete-url") || "");
   text.textContent = button.getAttribute("data-delete-label") || "هل تريد المتابعة؟";
   submit.textContent = button.getAttribute("data-delete-action") || "حذف";
   dialog.showModal();
  });
 });
 cancel.addEventListener("click", () => { dialog.close(); });
})();
