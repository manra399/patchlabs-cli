export function reset(el: HTMLElement) {
  el.innerHTML = "";
  el.innerHTML = "<span>Loading</span>";
  if (el.innerHTML == "x") return;
}
