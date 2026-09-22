const POINTS = [100, 200, 300, 400, 500];
const BOARD = [
  { title: "Основы глобализации", ids: ["q01", "q02", "q03", "q04", "q05"] },
  { title: "Этапы глобализации", ids: ["q06", "q07", "q08", "q09", "q10"] },
  { title: "Теории и концепции", ids: ["q11", "q12", "q13", "q14", "q15"] },
  { title: "Три направления", ids: ["q16", "q17", "q18", "q19", "q20"] },
  { title: "Стиглиц и трансформационисты", ids: ["q21", "q22", "q23", "q24", "q25"] },
];

const state = {
  questions: new Map(),
  selected: null,
  used: new Set(JSON.parse(localStorage.getItem("usedCellsV2") || "[]")),
  teamScores: JSON.parse(localStorage.getItem("teamScoresV2") || "[0,0]"),
  currentTeam: Number(localStorage.getItem("currentTeamV2") || "0"),
  answerKey: JSON.parse(sessionStorage.getItem("answerKeyV5") || "null"),
};

state.admin = Boolean(state.answerKey);

const els = {
  adminButton: document.querySelector("#adminButton"),
  adminDialog: document.querySelector("#adminDialog"),
  passwordInput: document.querySelector("#passwordInput"),
  unlockButton: document.querySelector("#unlockButton"),
  loginError: document.querySelector("#loginError"),
  boardView: document.querySelector("#boardView"),
  board: document.querySelector("#board"),
  teamOneCard: document.querySelector("#teamOneCard"),
  teamTwoCard: document.querySelector("#teamTwoCard"),
  teamOneScore: document.querySelector("#teamOneScore"),
  teamTwoScore: document.querySelector("#teamTwoScore"),
  turnText: document.querySelector("#turnText"),
  resetButton: document.querySelector("#resetButton"),
  questionView: document.querySelector("#questionView"),
  backButton: document.querySelector("#backButton"),
  questionMeta: document.querySelector("#questionMeta"),
  questionTitle: document.querySelector("#questionTitle"),
  questionText: document.querySelector("#questionText"),
  answerCard: document.querySelector("#answerCard"),
  answerText: document.querySelector("#answerText"),
  answerNote: document.querySelector("#answerNote"),
  showAnswerButton: document.querySelector("#showAnswerButton"),
  correctButton: document.querySelector("#correctButton"),
  wrongButton: document.querySelector("#wrongButton"),
  doneButton: document.querySelector("#doneButton"),
};

function base64ToBytes(value) {
  return Uint8Array.from(atob(value), (char) => char.charCodeAt(0));
}

function joinBytes(...parts) {
  const size = parts.reduce((total, part) => total + part.length, 0);
  const joined = new Uint8Array(size);
  let offset = 0;

  parts.forEach((part) => {
    joined.set(part, offset);
    offset += part.length;
  });

  return joined;
}

function sameBytes(left, right) {
  if (left.length !== right.length) return false;
  let diff = 0;

  for (let index = 0; index < left.length; index += 1) {
    diff |= left[index] ^ right[index];
  }

  return diff === 0;
}

async function deriveKeys(password, salt, iterations) {
  const sourceKey = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(password),
    "PBKDF2",
    false,
    ["deriveBits"],
  );

  const bits = await crypto.subtle.deriveBits(
    { name: "PBKDF2", hash: "SHA-256", salt, iterations },
    sourceKey,
    512,
  );

  const material = new Uint8Array(bits);
  return {
    aesKey: material.slice(0, 32),
    macKey: material.slice(32, 64),
  };
}

async function decryptAnswerKey(password) {
  const response = await fetch("answers.lock.json", { cache: "no-store" });
  if (!response.ok) {
    throw new Error("Не удалось загрузить ключ");
  }

  const lock = await response.json();
  const salt = base64ToBytes(lock.salt);
  const iv = base64ToBytes(lock.iv);
  const ciphertext = base64ToBytes(lock.ciphertext);
  const expectedHmac = base64ToBytes(lock.hmac);
  const { aesKey, macKey } = await deriveKeys(password, salt, lock.iterations);
  const macInput = joinBytes(salt, iv, ciphertext);
  const hmacKey = await crypto.subtle.importKey(
    "raw",
    macKey,
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );
  const actualHmac = new Uint8Array(await crypto.subtle.sign("HMAC", hmacKey, macInput));

  if (!sameBytes(actualHmac, expectedHmac)) {
    throw new Error("Неверный пароль");
  }

  const key = await crypto.subtle.importKey("raw", aesKey, "AES-CBC", false, ["decrypt"]);
  const plain = await crypto.subtle.decrypt({ name: "AES-CBC", iv }, key, ciphertext);
  return JSON.parse(new TextDecoder().decode(plain));
}

function teamName(index = state.currentTeam) {
  return `Команда ${index + 1}`;
}

function storageCellId(cell) {
  return `${cell.categoryIndex}-${cell.pointIndex}`;
}

function questionByCell(cell) {
  return state.questions.get(cell.id);
}

function answerFor(question) {
  return state.answerKey?.answers?.[question.id] || null;
}

function nextTeam() {
  state.currentTeam = state.currentTeam === 0 ? 1 : 0;
}

function saveProgress() {
  localStorage.setItem("usedCellsV2", JSON.stringify([...state.used]));
  localStorage.setItem("teamScoresV2", JSON.stringify(state.teamScores));
  localStorage.setItem("currentTeamV2", String(state.currentTeam));
}

function renderScores() {
  els.teamOneScore.textContent = state.teamScores[0];
  els.teamTwoScore.textContent = state.teamScores[1];
  els.turnText.textContent = `Ход: ${teamName()}`;
  els.teamOneCard.classList.toggle("active", state.currentTeam === 0);
  els.teamTwoCard.classList.toggle("active", state.currentTeam === 1);
}

function renderBoard() {
  els.board.innerHTML = "";
  renderScores();

  BOARD.forEach((category) => {
    const label = document.createElement("div");
    label.className = "board-cell category-cell";
    label.textContent = category.title;
    els.board.append(label);
  });

  POINTS.forEach((points, pointIndex) => {
    BOARD.forEach((category, categoryIndex) => {
      const cell = { id: category.ids[pointIndex], categoryIndex, pointIndex, points };
      const button = document.createElement("button");
      button.type = "button";
      button.className = "board-cell points-cell";
      button.textContent = points;

      if (state.used.has(storageCellId(cell))) {
        button.classList.add("used");
        button.disabled = true;
      }

      button.addEventListener("click", () => openQuestion(cell));
      els.board.append(button);
    });
  });
}

function openQuestion(cell) {
  const question = questionByCell(cell);
  if (!question || state.used.has(storageCellId(cell))) return;

  state.selected = cell;
  els.boardView.classList.add("hidden");
  els.questionView.classList.remove("hidden");
  els.answerCard.classList.add("hidden");
  els.answerText.textContent = "";
  els.answerNote.textContent = "";
  els.answerNote.hidden = true;
  els.questionMeta.textContent = `${teamName()} / ${BOARD[cell.categoryIndex].title} / ${cell.points}`;
  els.questionTitle.textContent = `Вопрос за ${cell.points}`;
  els.questionText.textContent = question.question;
  els.correctButton.hidden = !state.admin;
  els.wrongButton.hidden = !state.admin;
}

function showBoard({ markUsed = false, switchTurn = false } = {}) {
  if (markUsed && state.selected) {
    state.used.add(storageCellId(state.selected));
  }

  if (switchTurn) {
    nextTeam();
  }

  saveProgress();
  state.selected = null;
  els.questionView.classList.add("hidden");
  els.boardView.classList.remove("hidden");
  renderBoard();
}

function revealAnswer() {
  const question = questionByCell(state.selected);
  const key = question ? answerFor(question) : null;
  els.answerCard.classList.remove("hidden");

  if (!key) {
    els.answerText.textContent = "Ответ закрыт";
    els.answerNote.textContent = "";
    els.answerNote.hidden = true;
    return;
  }

  els.answerText.textContent = key.answer;
  els.answerNote.textContent = key.explanation || "";
  els.answerNote.hidden = !key.explanation;
}

function applyScore(delta) {
  if (!state.selected) return;
  state.teamScores[state.currentTeam] += delta;
  state.used.add(storageCellId(state.selected));
  nextTeam();
  saveProgress();
  showBoard();
}

async function loadQuestions() {
  const response = await fetch("questions.json", { cache: "no-store" });
  if (!response.ok) {
    throw new Error("Не удалось загрузить вопросы");
  }

  const questions = await response.json();
  state.questions = new Map(questions.map((question) => [question.id, question]));
  renderBoard();
}

els.backButton.addEventListener("click", () => showBoard());
els.doneButton.addEventListener("click", () => showBoard({ markUsed: true, switchTurn: true }));
els.showAnswerButton.addEventListener("click", revealAnswer);
els.correctButton.addEventListener("click", () => applyScore(state.selected.points));
els.wrongButton.addEventListener("click", () => applyScore(-state.selected.points));

els.resetButton.addEventListener("click", () => {
  state.teamScores = [0, 0];
  state.currentTeam = 0;
  state.used.clear();
  saveProgress();
  renderBoard();
});

els.adminButton.addEventListener("click", () => {
  els.loginError.textContent = "";
  els.passwordInput.value = "";
  els.adminDialog.showModal();
  requestAnimationFrame(() => els.passwordInput.focus());
});

els.unlockButton.addEventListener("click", async () => {
  els.loginError.textContent = "";

  try {
    state.answerKey = await decryptAnswerKey(els.passwordInput.value);
  } catch (error) {
    els.loginError.textContent = error.message || "Неверный пароль";
    return;
  }

  state.admin = true;
  sessionStorage.setItem("answerKeyV5", JSON.stringify(state.answerKey));
  els.adminDialog.close();

  if (state.selected) {
    openQuestion(state.selected);
  }
});

els.passwordInput.addEventListener("keydown", (event) => {
  if (event.key === "Enter") {
    event.preventDefault();
    els.unlockButton.click();
  }
});

loadQuestions().catch((error) => {
  els.board.innerHTML = "";
  const message = document.createElement("div");
  message.className = "board-cell category-cell";
  message.textContent = error.message;
  els.board.append(message);
});
