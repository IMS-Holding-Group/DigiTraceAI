(function () {
 const button = document.getElementById("analyze-button");
 const status = document.getElementById("analyze-status");
 if (!button) return;
 const label = button.querySelector("span") || button;
 button.addEventListener("click", () => {
  button.disabled = true;
  label.textContent = "جارٍ التحليل";
  if (status) status.textContent = "جارٍ التحليل";
  fetch(button.getAttribute("data-analyze-url"), {
   method: "POST",
   headers: {
    "X-CSRF-Token": button.getAttribute("data-csrf") || "",
    "Accept": "application/json"
   }
  }).then((response) => response.json().then((data) => ({ ok: response.ok, data: data }))).then((result) => {
   if (result.ok && result.data && result.data.ok && result.data.redirect) {
    window.location.assign(result.data.redirect);
    return;
   }
   button.disabled = false;
   label.textContent = "تحليل البيانات";
   if (status) status.textContent = (result.data && result.data.error) || "تعذر إكمال التحليل، يمكن إعادة المحاولة";
  }).catch(() => {
   button.disabled = false;
   label.textContent = "تحليل البيانات";
   if (status) status.textContent = "تعذر إكمال التحليل، يمكن إعادة المحاولة";
  });
 });
})();