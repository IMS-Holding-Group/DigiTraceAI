(function () {
 const root = document.getElementById("results-root");
 if (!root) return;
 const list = document.getElementById("events-list");
 const pager = document.getElementById("pager");
 const orderButton = document.getElementById("order-button");
 const resetButton = document.getElementById("reset-button");
 const note = document.getElementById("filter-note");
 const dialog = document.getElementById("event-dialog");
 const dialogBody = document.getElementById("event-dialog-body");
 const dialogClose = document.getElementById("event-close");
 const dialogGroup = document.getElementById("event-group");
 let timer = 0;
 let groupsLoaded = false;
 function text(value) {
  return value == null ? "" : String(value);
 }
 function badgeClass(level) {
  if (level === "حرج") return "badge badge-critical";
  if (level === "عالٍ") return "badge badge-high";
  if (level === "متوسط") return "badge badge-medium";
  return "badge badge-low";
 }
 function show(name) {
  document.querySelectorAll(".tab").forEach((tab) => {
   if (tab.getAttribute("data-tab") === name) tab.classList.add("is-active");
   else tab.classList.remove("is-active");
  });
  document.querySelectorAll(".tab-panel").forEach((panel) => {
   if (panel.id === "panel-" + name) panel.classList.remove("is-hidden");
   else panel.classList.add("is-hidden");
  });
  if (name === "groups" && !groupsLoaded) loadGroups();
 }
 function fieldValue(id) {
  const node = document.getElementById(id);
  return node ? node.value.trim() : "";
 }
 function toUtc(value) {
  const match = String(value || "").match(/^(\d{4}-\d{2}-\d{2})T(\d{2}:\d{2})/);
  if (!match) return "";
  return match[1] + "T" + match[2] + ":00Z";
 }
 function query(page) {
  const params = new URLSearchParams();
  params.set("page", String(page));
  params.set("per_page", "100");
  params.set("order", orderButton.getAttribute("data-order") || "asc");
  params.set("include_noise", document.getElementById("include_noise").checked ? "1" : "0");
  const q = fieldValue("q");
  const source = fieldValue("source");
  const user = fieldValue("user");
  const device = fieldValue("device");
  const ip = fieldValue("ip");
  const file = fieldValue("file");
  const group = fieldValue("group");
  const from = toUtc(fieldValue("from"));
  const to = toUtc(fieldValue("to"));
  if (q) params.set("q", q);
  if (source) params.set("source", source);
  if (user) params.set("user", user);
  if (device) params.set("device", device);
  if (ip) params.set("ip", ip);
  if (file) params.set("file", file);
  if (group) params.set("group", group);
  if (from) params.set("from", from);
  if (to) params.set("to", to);
  const levels = [];
  document.querySelectorAll("input[name='importance']:checked").forEach((box) => { levels.push(box.value); });
  if (levels.length) params.set("importance", levels.join(","));
  return params.toString();
 }
 function cell(row, value, className) {
  const item = document.createElement("td");
  if (className) item.className = className;
  item.textContent = text(value);
  row.appendChild(item);
  return item;
 }
 function metaLine(event) {
  const parts = [event.source_label, event.username, event.device, event.ip_address || event.dest_ip, event.file_path || event.url];
  return parts.filter((part) => text(part)).join(" · ");
 }
 function renderEvents(events) {
  list.textContent = "";
  if (!events.length) {
   const empty = document.createElement("p");
   empty.className = "empty";
   empty.textContent = "لا توجد أحداث مطابقة";
   list.appendChild(empty);
   return;
  }
  let lastDay = "";
  events.forEach((event, index) => {
   const day = text(event.event_time).slice(0, 10);
   if (day && day !== lastDay) {
    lastDay = day;
    const mark = document.createElement("p");
    mark.className = "day-mark";
    mark.appendChild(window.DigiTrace.fmtDate(event.event_time));
    list.appendChild(mark);
   }
   const item = document.createElement("article");
   item.className = "event";
   item.tabIndex = 0;
   item.style.animationDelay = Math.min(index, 8) * 40 + "ms";
   const time = document.createElement("div");
   time.className = "event-time";
   time.appendChild(window.DigiTrace.fmtDt(event.event_time));
   item.appendChild(time);
   const info = document.createElement("div");
   const head = document.createElement("div");
   head.className = "event-head";
   const title = document.createElement("h3");
   title.textContent = text(event.event_label);
   head.appendChild(title);
   const badge = document.createElement("span");
   badge.className = badgeClass(event.importance_level);
   badge.textContent = text(event.importance_level);
   head.appendChild(badge);
   info.appendChild(head);
   const meta = document.createElement("p");
   meta.className = "hint";
   meta.textContent = metaLine(event);
   info.appendChild(meta);
   if (event.group_label) {
    const group = document.createElement("p");
    group.className = "hint";
    group.textContent = text(event.group_label);
    info.appendChild(group);
   }
   item.appendChild(info);
   item.addEventListener("click", () => openEvent(event.event_id));
   item.addEventListener("keydown", (keyEvent) => {
    if (keyEvent.key === "Enter" || keyEvent.key === " ") {
     keyEvent.preventDefault();
     openEvent(event.event_id);
    }
   });
   list.appendChild(item);
  });
 }
 function renderPager(page, pages) {
  pager.textContent = "";
  if (pages <= 1) return;
  for (let number = 1; number <= pages; number += 1) {
   const link = document.createElement("button");
   link.type = "button";
   link.className = number === page ? "pager-link is-active" : "pager-link";
   link.textContent = String(number);
   link.addEventListener("click", () => loadEvents(number));
   pager.appendChild(link);
  }
 }
 function placeNote(message) {
  list.textContent = "";
  const noteItem = document.createElement("p");
  noteItem.className = "empty";
  noteItem.textContent = message;
  list.appendChild(noteItem);
 }
 function loadEvents(page) {
  placeNote("جارٍ التحميل");
  fetch(root.getAttribute("data-events-url") + "?" + query(page), { headers: { "Accept": "application/json" } }).then((response) => {
   if (!response.ok) throw new Error("load");
   return response.json();
  }).then((data) => {
   renderEvents(data.events || []);
   renderPager(data.page || 1, data.pages || 1);
  }).catch(() => placeNote("تعذر تحميل الأحداث"));
 }
 function line(parent, label, value) {
  const paragraph = document.createElement("p");
  const title = document.createElement("span");
  title.className = "stat-label";
  title.textContent = label + ": ";
  paragraph.appendChild(title);
  if (value && value.nodeType) paragraph.appendChild(value);
  else paragraph.appendChild(document.createTextNode(text(value)));
  parent.appendChild(paragraph);
 }
 function openEvent(eventId) {
  dialogBody.textContent = "";
  const waiting = document.createElement("p");
  waiting.textContent = "جارٍ التحميل";
  dialogBody.appendChild(waiting);
  dialog.showModal();
  const base = root.getAttribute("data-events-url");
  fetch(base + "/" + eventId, { headers: { "Accept": "application/json" } }).then((response) => {
   if (!response.ok) throw new Error("detail");
   return response.json();
  }).then((data) => {
   const event = data.event || {};
   dialogBody.textContent = "";
   line(dialogBody, "الوقت", window.DigiTrace.fmtDt(event.event_time));
   line(dialogBody, "المصدر", event.source_label);
   line(dialogBody, "النوع", event.event_label);
   line(dialogBody, "الإجراء", event.action);
   line(dialogBody, "النتيجة", event.result);
   line(dialogBody, "المستخدم", event.username);
   line(dialogBody, "الجهاز", event.device);
   line(dialogBody, "عنوان IP", event.ip_address);
   line(dialogBody, "عنوان الوجهة", event.dest_ip);
   line(dialogBody, "الملف", event.file_path);
   line(dialogBody, "الرابط", event.url);
   line(dialogBody, "التفاصيل", event.details);
   line(dialogBody, "الأهمية", event.importance_level);
   line(dialogBody, "الدرجة", event.importance_score);
   line(dialogBody, "الشذوذ", event.anomaly_score);
   line(dialogBody, "المرحلة", event.stage_label);
   line(dialogBody, "التكرار", event.repeat_count);
   line(dialogBody, "المجموعة", event.group_label);
   const reasonsTitle = document.createElement("p");
   reasonsTitle.textContent = "أسباب الدرجة";
   dialogBody.appendChild(reasonsTitle);
   const list = document.createElement("ul");
   (event.reasons || []).forEach((reason) => {
    const item = document.createElement("li");
    item.textContent = text(reason);
    list.appendChild(item);
   });
   dialogBody.appendChild(list);
   const rawTitle = document.createElement("p");
   rawTitle.textContent = "البيانات الخام";
   dialogBody.appendChild(rawTitle);
   const raw = document.createElement("pre");
   raw.className = "raw-block";
   raw.textContent = text(event.raw_data);
   dialogBody.appendChild(raw);
   if (event.group_id) {
    dialogGroup.hidden = false;
    dialogGroup.dataset.groupId = String(event.group_id);
    dialogGroup.dataset.groupLabel = text(event.group_label);
   } else dialogGroup.hidden = true;
  }).catch(() => {
   dialogBody.textContent = "";
   const fail = document.createElement("p");
   fail.textContent = "تعذر تحميل تفاصيل الحدث";
   dialogBody.appendChild(fail);
  });
 }
 function applyGroup(id, label) {
  document.getElementById("group").value = text(id);
  note.textContent = id ? "تصفية حسب المجموعة: " + text(label) : "";
  show("timeline");
  loadEvents(1);
 }
 function loadGroups() {
  const target = document.getElementById("groups-body");
  fetch(root.getAttribute("data-groups-url"), { headers: { "Accept": "application/json" } }).then((response) => {
   if (!response.ok) throw new Error("groups");
   return response.json();
  }).then((data) => {
   groupsLoaded = true;
   target.textContent = "";
   const groups = data.groups || [];
   if (!groups.length) {
    const row = document.createElement("tr");
    const item = document.createElement("td");
    item.colSpan = 11;
    item.textContent = "لا توجد مجموعات";
    row.appendChild(item);
    target.appendChild(row);
    return;
   }
   groups.forEach((group) => {
    const row = document.createElement("tr");
    cell(row, group.group_label);
    const risk = document.createElement("td");
    const badge = document.createElement("span");
    badge.className = badgeClass(group.risk_level);
    badge.textContent = text(group.risk_level) + " " + text(group.risk_score);
    risk.appendChild(badge);
    row.appendChild(risk);
    const from = document.createElement("td");
    from.appendChild(window.DigiTrace.fmtDt(group.start_time));
    row.appendChild(from);
    const to = document.createElement("td");
    to.appendChild(window.DigiTrace.fmtDt(group.end_time));
    row.appendChild(to);
    cell(row, group.event_count, "ltr");
    cell(row, group.key_event_count, "ltr");
    cell(row, group.main_user, "ltr");
    cell(row, group.main_device, "ltr");
    cell(row, group.main_ip, "ltr");
    cell(row, (group.stages || []).join("، "));
    const action = document.createElement("td");
    const button = document.createElement("button");
    button.type = "button";
    button.className = "btn btn-ghost";
    button.textContent = "عرض أحداث المجموعة";
    button.addEventListener("click", () => applyGroup(group.group_id, group.group_label));
    action.appendChild(button);
    row.appendChild(action);
    target.appendChild(row);
   });
  }).catch(() => {
   target.textContent = "";
   const row = document.createElement("tr");
   const item = document.createElement("td");
   item.colSpan = 11;
   item.textContent = "تعذر تحميل المجموعات";
   row.appendChild(item);
   target.appendChild(row);
  });
 }
 function schedule() {
  window.clearTimeout(timer);
  timer = window.setTimeout(() => loadEvents(1), 300);
 }
 document.querySelectorAll(".tab").forEach((tab) => {
  tab.addEventListener("click", () => {
   const name = tab.getAttribute("data-tab");
   show(name);
   if (name === "timeline") loadEvents(1);
  });
 });
 ["q", "user", "device", "ip", "file"].forEach((id) => {
  document.getElementById(id).addEventListener("input", schedule);
 });
 ["source", "from", "to"].forEach((id) => {
  document.getElementById(id).addEventListener("change", () => loadEvents(1));
 });
 document.getElementById("include_noise").addEventListener("change", () => loadEvents(1));
 document.querySelectorAll("input[name='importance']").forEach((box) => {
  box.addEventListener("change", () => loadEvents(1));
 });
 orderButton.addEventListener("click", () => {
  const next = orderButton.getAttribute("data-order") === "desc" ? "asc" : "desc";
  orderButton.setAttribute("data-order", next);
  orderButton.textContent = next === "desc" ? "الأقدم أولاً" : "الأحدث أولاً";
  loadEvents(1);
 });
 resetButton.addEventListener("click", () => {
  document.getElementById("filters").reset();
  document.getElementById("group").value = "";
  orderButton.setAttribute("data-order", "asc");
  orderButton.textContent = "الأحدث أولاً";
  note.textContent = "";
  loadEvents(1);
 });
 dialogClose.addEventListener("click", () => { dialog.close(); });
 dialogGroup.addEventListener("click", () => {
  applyGroup(dialogGroup.dataset.groupId || "", dialogGroup.dataset.groupLabel || "");
  dialog.close();
 });
})();
