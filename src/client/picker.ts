// Kept free of the crypto library so names can be searched as soon as the page opens.
interface Person {
  keyId: number;
  name: string;
}

const people = JSON.parse(document.getElementById("people-data")?.textContent || "[]") as Person[];
const form = document.getElementById("compose") as HTMLFormElement;
const input = document.getElementById("recipient-search") as HTMLInputElement;
const list = document.getElementById("recipient-list") as HTMLUListElement;
const hidden = document.getElementById("recipient") as HTMLInputElement;
let shown = people;
let active = -1;

if (people.length === 0) {
  form.hidden = true;
  (document.getElementById("no-people") as HTMLElement).hidden = false;
}

function render(): void {
  input.removeAttribute("aria-activedescendant");
  list.replaceChildren(
    ...(shown.length === 0
      ? [Object.assign(document.createElement("li"), { className: "picker-empty", textContent: "No one with that name" })]
      : shown.map((person, index) => {
          const item = document.createElement("li");
          item.id = `person-${person.keyId}`;
          item.role = "option";
          item.textContent = person.name;
          item.setAttribute("aria-selected", String(index === active));
          item.classList.toggle("active", index === active);
          item.addEventListener("mousedown", (event) => event.preventDefault());
          item.addEventListener("click", () => choose(person));
          return item;
        })),
  );
  const current = list.children[active] as HTMLElement | undefined;
  if (shown.length > 0 && current) {
    input.setAttribute("aria-activedescendant", current.id);
    current.scrollIntoView({ block: "nearest" });
  }
}

function open(): void {
  list.hidden = false;
  input.setAttribute("aria-expanded", "true");
  render();
}

function close(): void {
  list.hidden = true;
  input.setAttribute("aria-expanded", "false");
  input.removeAttribute("aria-activedescendant");
  active = -1;
}

function setRecipient(value: string): void {
  hidden.value = value;
  hidden.dispatchEvent(new Event("change"));
}

function choose(person: Person): void {
  input.value = person.name;
  setRecipient(String(person.keyId));
  close();
}

function filter(): void {
  const query = input.value.trim().toLowerCase();
  shown = people.filter((person) => person.name.toLowerCase().includes(query));
  active = -1;
}

input.addEventListener("input", () => {
  setRecipient("");
  filter();
  open();
});

const showAll = () => {
  shown = hidden.value ? people : shown;
  if (!hidden.value) filter();
  if (hidden.value) input.select();
  open();
};
input.addEventListener("focus", showAll);
input.addEventListener("click", () => {
  if (list.hidden) showAll();
});
input.addEventListener("blur", () => {
  const typed = input.value.trim().toLowerCase();
  const exact = !hidden.value && typed ? people.find((person) => person.name.toLowerCase() === typed) : undefined;
  if (exact) choose(exact);
  close();
});

input.addEventListener("keydown", (event) => {
  if (event.key === "ArrowDown" || event.key === "ArrowUp") {
    event.preventDefault();
    if (list.hidden) open();
    if (shown.length === 0) return;
    active = event.key === "ArrowDown" ? (active + 1) % shown.length : (active <= 0 ? shown.length : active) - 1;
    render();
  } else if (event.key === "Enter" && !list.hidden) {
    event.preventDefault();
    const person = active >= 0 ? shown[active] : shown.length === 1 ? shown[0] : undefined;
    if (person) choose(person);
  } else if (event.key === "Escape") {
    close();
  }
});

form.addEventListener("reset", () => {
  setRecipient("");
  shown = people;
  close();
});
