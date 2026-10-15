(function () {
 function pad(value) { return String(value).padStart(2, "0"); }
 function parts(iso) {
  const match = String(iso || "").match(/^(\d{4})-(\d{2})-(\d{2})[T ](\d{2}):(\d{2})/);
  if (!match) return null;
  return {
   year: Number(match[1]),
   month: Number(match[2]),
   day: Number(match[3]),
   hour: Number(match[4]),
   minute: pad(match[5])
  };
 }
 function hourLabel(hour24) {
  const suffix = hour24 < 12 ? "ص" : "م";
  let hour = hour24 % 12;
  if (hour === 0) hour = 12;
  return { hour: hour, suffix: suffix };
 }
 function makeDt(iso, withTime) {
  const parsed = parts(iso);
  if (!parsed) return document.createTextNode("");
  const wrap = document.createElement("span");
  wrap.className = "dt";
  wrap.dir = "rtl";
  const date = parsed.year + "/" + parsed.month + "/" + parsed.day + "م";
  if (!withTime) {
   wrap.textContent = date;
   return wrap;
  }
  const clock = hourLabel(parsed.hour);
  wrap.textContent = date + " " + clock.hour + ":" + parsed.minute + clock.suffix;
  return wrap;
 }
 window.DigiTrace = {
  fmtDt: function (iso) { return makeDt(iso, true); },
  fmtDate: function (iso) { return makeDt(iso, false); }
 };
 document.querySelectorAll("[data-toggle-password]").forEach((button) => {
  button.addEventListener("click", () => {
   const input = document.getElementById(button.getAttribute("data-toggle-password"));
   if (!input) return;
   const shown = input.getAttribute("type") === "text";
   input.setAttribute("type", shown ? "password" : "text");
   button.textContent = shown ? "إظهار" : "إخفاء";
  });
 });
})();
