// CampusFind Chatbot Widget (Vanilla JavaScript)
// Implements a modular, self-invoking chatbot component that injects UI elements,
// manages state and user interactions, and delivers rule-based automated responses.

(() => {
  // ============================================================
  //  GUARD: only inject once
  // ============================================================
  const ROOT_ID = "cf-chatbot-root";
  if (document.getElementById(ROOT_ID)) return;

  const normalizePath = (p) => {
    if (!p) return "/";
    const trimmed = p.replace(/\/+$/, "");
    return trimmed === "" ? "/" : trimmed;
  };

  const currentPath = normalizePath(window.location.pathname);

  // ============================================================
  //  1. STYLES
  // ============================================================
  const style = document.createElement("style");
  style.textContent = `
@import url('https://fonts.googleapis.com/css2?family=DM+Sans:wght@400;500;600&display=swap');

#cf-chatbot-root * { box-sizing: border-box; font-family: 'DM Sans', Arial, sans-serif; }

#cf-chatbot-overlay {
  position: fixed; inset: 0;
  background: rgba(0,0,0,0.18);
  backdrop-filter: blur(4px);
  -webkit-backdrop-filter: blur(4px);
  opacity: 0; pointer-events: none;
  transition: opacity 0.25s ease; z-index: 9998;
}
#cf-chatbot-overlay.is-open { opacity: 1; pointer-events: auto; }

#cf-chatbot-root {
  position: fixed; right: 22px; bottom: 22px; z-index: 9999;
}

/* Toggle button */
#cf-chatbot-toggle {
  width: 56px; height: 56px; border-radius: 999px;
  background: linear-gradient(135deg, #007bff, #0056d6);
  color: #fff; border: none; cursor: pointer;
  box-shadow: 0 8px 24px rgba(0,123,255,0.45);
  display: grid; place-items: center;
  transition: transform 0.2s, box-shadow 0.2s;
}
#cf-chatbot-toggle:hover {
  transform: scale(1.07);
  box-shadow: 0 12px 32px rgba(0,123,255,0.55);
}

/* Panel */
#cf-chatbot-panel {
  position: absolute; right: 0; bottom: 70px;
  width: 370px; height: 540px;
  background: #fff; border-radius: 16px;
  box-shadow: 0 20px 60px rgba(0,0,0,0.22);
  display: none; flex-direction: column; overflow: hidden;
  animation: cf-slide-up 0.22s ease;
}
#cf-chatbot-panel.is-open { display: flex; }
@keyframes cf-slide-up {
  from { opacity: 0; transform: translateY(16px); }
  to   { opacity: 1; transform: translateY(0); }
}

/* Header */
.cf-header {
  background: linear-gradient(135deg, #007bff, #0056d6);
  color: #fff; padding: 12px 14px;
  display: flex; align-items: center; gap: 10px;
}
.cf-header-avatar {
  width: 36px; height: 36px; border-radius: 50%;
  background: rgba(255,255,255,0.2);
  display: grid; place-items: center; flex-shrink: 0;
}
.cf-header-info { flex: 1; }
.cf-header-name { font-weight: 600; font-size: 14px; }
.cf-header-status { font-size: 11px; opacity: 0.8; display: flex; align-items: center; gap: 4px; }
.cf-status-dot {
  width: 7px; height: 7px; border-radius: 50%;
  background: #4eff91; display: inline-block;
}
.cf-header-close {
  background: rgba(255,255,255,0.15); color: #fff;
  border: none; padding: 6px 11px; border-radius: 8px;
  cursor: pointer; font-size: 12px; font-family: inherit;
  transition: background 0.15s;
}
.cf-header-close:hover { background: rgba(255,255,255,0.28); }

/* Body / messages */
.cf-body {
  flex: 1; padding: 12px; overflow-y: auto;
  background: #f5f7fb; display: flex; flex-direction: column; gap: 6px;
}
.cf-body::-webkit-scrollbar { width: 4px; }
.cf-body::-webkit-scrollbar-thumb { background: #cdd3de; border-radius: 4px; }

/* Messages */
.cf-msg {
  padding: 9px 12px; border-radius: 12px;
  max-width: 82%; font-size: 13.5px; line-height: 1.45;
  animation: cf-pop 0.18s ease;
}
@keyframes cf-pop {
  from { opacity: 0; transform: scale(0.94); }
  to   { opacity: 1; transform: scale(1); }
}
.cf-msg-user {
  background: linear-gradient(135deg, #007bff, #0056d6);
  color: #fff; margin-left: auto; border-bottom-right-radius: 3px;
}
.cf-msg-bot {
  background: #fff; color: #222;
  border-bottom-left-radius: 3px;
  box-shadow: 0 1px 4px rgba(0,0,0,0.08);
}

/* Typing indicator */
.cf-typing {
  background: #fff; padding: 10px 14px; border-radius: 12px;
  border-bottom-left-radius: 3px; width: 56px;
  box-shadow: 0 1px 4px rgba(0,0,0,0.08);
  display: flex; gap: 4px; align-items: center;
}
.cf-typing span {
  width: 7px; height: 7px; border-radius: 50%;
  background: #aaa; display: inline-block;
  animation: cf-bounce 1.2s infinite;
}
.cf-typing span:nth-child(2) { animation-delay: 0.2s; }
.cf-typing span:nth-child(3) { animation-delay: 0.4s; }
@keyframes cf-bounce {
  0%, 60%, 100% { transform: translateY(0); }
  30% { transform: translateY(-5px); }
}

/* Suggestion chips */
.cf-chips {
  display: flex; flex-wrap: wrap; gap: 6px;
  padding: 4px 0 2px 0; max-width: 100%;
}
.cf-chip {
  padding: 5px 11px; border-radius: 999px; font-size: 12.5px;
  border: 1.5px solid #007bff; color: #007bff;
  background: #fff; cursor: pointer; font-family: inherit;
  transition: background 0.15s, color 0.15s, transform 0.1s;
  white-space: nowrap;
}
.cf-chip:hover {
  background: #007bff; color: #fff; transform: scale(1.03);
}

/* Input bar */
.cf-input-bar {
  display: flex; border-top: 1px solid #e8eaf0;
  background: #fff; align-items: center; padding: 6px 8px; gap: 6px;
}
.cf-input-bar input {
  flex: 1; padding: 9px 12px; border: 1.5px solid #e0e4ef;
  border-radius: 10px; outline: none; font-size: 13.5px;
  font-family: inherit; transition: border-color 0.15s; background: #f5f7fb;
}
.cf-input-bar input:focus { border-color: #007bff; background: #fff; }
.cf-input-bar button {
  padding: 9px 14px; background: linear-gradient(135deg, #007bff, #0056d6);
  color: #fff; border: none; border-radius: 10px;
  cursor: pointer; font-size: 13px; font-family: inherit; font-weight: 600;
  transition: opacity 0.15s, transform 0.1s;
}
.cf-input-bar button:hover { opacity: 0.9; transform: scale(1.03); }

/* Divider label */
.cf-divider {
  text-align: center; font-size: 11px; color: #aaa;
  margin: 4px 0; letter-spacing: 0.5px;
}

@media (max-width: 480px) {
  #cf-chatbot-panel {
    width: calc(100vw - 28px); right: 14px; height: 78vh;
  }
}
  `.trim();
  document.head.appendChild(style);

  // ============================================================
  //  2. HTML STRUCTURE
  // ============================================================
  const overlay = document.createElement("div");
  overlay.id = "cf-chatbot-overlay";
  document.body.appendChild(overlay);

  const root = document.createElement("div");
  root.id = ROOT_ID;
  root.innerHTML = `
    <button id="cf-chatbot-toggle" aria-expanded="false" title="Chat with us">
      <svg width="24" height="24" viewBox="0 0 24 24" fill="none">
        <path d="M7 9h10M7 13h6" stroke="currentColor" stroke-width="2" stroke-linecap="round"/>
        <path d="M20 12a8 8 0 1 1-3.2-6.4L20 5v7Z" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/>
      </svg>
    </button>
    <div id="cf-chatbot-panel" role="dialog" aria-label="Lost and Found Chatbot">
      <div class="cf-header">
        <div class="cf-header-avatar">
          <svg width="18" height="18" viewBox="0 0 24 24" fill="none">
            <circle cx="12" cy="8" r="4" stroke="white" stroke-width="2"/>
            <path d="M4 20c0-4 3.6-7 8-7s8 3 8 7" stroke="white" stroke-width="2" stroke-linecap="round"/>
          </svg>
        </div>
        <div class="cf-header-info">
          <div class="cf-header-name">Lost and Found Assistant</div>
          <div class="cf-header-status"><span class="cf-status-dot"></span> Online now</div>
        </div>
        <button class="cf-header-close" id="cf-chatbot-close">Close</button>
      </div>
      <div class="cf-body" id="cf-chatbot-body"></div>
      <div class="cf-input-bar">
        <input type="text" id="cf-chatbot-input" placeholder="Type a message..." autocomplete="off" />
        <button id="cf-chatbot-send">Send</button>
      </div>
    </div>
  `;
  document.body.appendChild(root);

  // element refs
  const panel    = document.getElementById("cf-chatbot-panel");
  const toggleEl = document.getElementById("cf-chatbot-toggle");
  const closeEl  = document.getElementById("cf-chatbot-close");
  const bodyEl   = document.getElementById("cf-chatbot-body");
  const inputEl  = document.getElementById("cf-chatbot-input");
  const sendEl   = document.getElementById("cf-chatbot-send");

  // ============================================================
  //  3. PANEL OPEN / CLOSE
  // ============================================================
  let greeted = false;

  const openPanel = () => {
    panel.classList.add("is-open");
    overlay.classList.add("is-open");
    toggleEl.setAttribute("aria-expanded", "true");
    inputEl.focus();
    if (!greeted) { greeted = true; showWelcome(); }
  };

  const closePanel = () => {
    panel.classList.remove("is-open");
    overlay.classList.remove("is-open");
    toggleEl.setAttribute("aria-expanded", "false");
  };

  toggleEl.addEventListener("click", () =>
    panel.classList.contains("is-open") ? closePanel() : openPanel()
  );
  closeEl.addEventListener("click", closePanel);
  overlay.addEventListener("click", closePanel);

  // ============================================================
  //  4. CONTEXT + CONVERSATION STATE
  // ============================================================
  let context = {
    intent:   null,   // "lost" | "found" | "search" | "claim"
    item:     null,   // e.g. "phone"
    location: null,
    time:     null
  };

  let step = null;


  // ============================================================
  //  5. KEYWORD LISTS
  // ============================================================
  const KW = {
    lost:      ["lost", "missing", "misplaced", "can't find", "cannot find", "not found", "lose"],
    found:     ["found", "picked up", "someone left", "i found", "got this"],
    search:    ["search", "find", "look for", "anyone found", "check"],
    claim:     ["claim", "this is mine", "belongs to me", "my item"],
    help:      ["help", "what should i do", "how do i", "how to"],

    itemImportant: ["id", "card", "passport", "hall ticket", "license", "aadhar", "driving"],
    itemAcademic:  ["notebook", "book", "assignment", "calculator", "notes", "textbook"],
    itemCommon:    ["phone", "mobile", "wallet", "bag", "keys", "key", "headphones",
                    "charger", "bottle", "laptop", "watch", "glasses", "earphones",
                    "umbrella", "pen", "pencil", "purse"],

    locations:  ["library", "canteen", "hostel", "classroom", "class", "lab", "parking",
                 "cafeteria", "ground", "auditorium", "toilet", "corridor", "office", "gate"],
    times:      ["today", "yesterday", "morning", "evening", "night", "last night",
                 "just now", "an hour", "this week"]
  };

  const has = (list, text) => list.some(w => text.includes(w));

  // ============================================================
  //  6. SUGGESTIONS MAP
  // ============================================================
  const SUGGESTIONS = {
    welcome:  ["I lost something", "I found something", "Search items", "How to claim?"],
    intent:   ["Lost Item", "Found Item", "Search", "Claim Item"],
    item:     ["Phone", "Wallet", "Bag", "Keys", "Book", "Laptop"],
    location: ["Library", "Canteen", "Hostel", "Classroom", "Lab", "Parking"],
    time:     ["Just now", "Today morning", "Yesterday", "Last night"],
    help:     ["Report Lost Item", "Report Found Item", "Search Items", "Track Status"]
  };

  // ============================================================
  //  7. DOM HELPERS
  // ============================================================
  const scrollDown = () => { bodyEl.scrollTop = bodyEl.scrollHeight; };

  const addMsg = (text, role) => {
    const d = document.createElement("div");
    d.className = `cf-msg cf-msg-${role}`;
    d.innerText = text;
    bodyEl.appendChild(d);
    scrollDown();
    return d;
  };

  const addChips = (chips) => {
    if (!chips || !chips.length) return;
    const wrap = document.createElement("div");
    wrap.className = "cf-chips";
    chips.forEach(label => {
      const btn = document.createElement("button");
      btn.className = "cf-chip";
      btn.textContent = label;
      btn.addEventListener("click", () => {
        const clean = label.trim();
        wrap.remove();
        handleUserMessage(clean);
      });
      wrap.appendChild(btn);
    });
    bodyEl.appendChild(wrap);
    scrollDown();
  };

  const addDivider = (text) => {
    const d = document.createElement("div");
    d.className = "cf-divider";
    d.textContent = text;
    bodyEl.appendChild(d);
  };

  const showTyping = () => {
    const d = document.createElement("div");
    d.className = "cf-typing";
    d.innerHTML = "<span></span><span></span><span></span>";
    bodyEl.appendChild(d);
    scrollDown();
    return () => d.remove();
  };

  const botReply = (text, chips, delay = 600) => {
    const removeTyping = showTyping();
    setTimeout(() => {
      removeTyping();
      addMsg(text, "bot");
      if (chips) addChips(chips);
    }, delay);
  };


  // ============================================================
  //  8. WELCOME MESSAGE
  // ============================================================
  const showWelcome = () => {
    addDivider("Today");
    botReply(
      "Hi there! I'm your Lost and Found Assistant.\n\nHow can I help you today?",
      SUGGESTIONS.welcome,
      500
    );
  };

  // ============================================================
  //  9. INTENT DETECTION
  // ============================================================
  const detectIntent = (text) => {
    const score = { lost: 0, found: 0, search: 0, claim: 0 };

    if (has(KW.lost,   text)) score.lost   += 3;
    if (has(KW.found,  text)) score.found  += 3;
    if (has(KW.search, text)) score.search += 2;
    if (has(KW.claim,  text)) score.claim  += 3;
    if (has(KW.help,   text)) { score.lost++; score.found++; }

    if (has(KW.itemImportant, text)) score.lost += 2;
    if (has(KW.itemAcademic,  text)) score.lost += 1;
    if (has(KW.itemCommon,    text)) score.lost += 1;

    const top = Object.keys(score).reduce((a, b) => score[a] >= score[b] ? a : b);
    return score[top] > 0 ? top : null;
  };

  const extractItem = (text) => {
    const all = [...KW.itemImportant, ...KW.itemAcademic, ...KW.itemCommon];
    return all.find(w => text.includes(w)) || null;
  };

  const extractLocation = (text) =>
    KW.locations.find(w => text.includes(w)) || null;

  const extractTime = (text) =>
    KW.times.find(w => text.includes(w)) || null;

  // ============================================================
  //  10. STEP-BY-STEP FLOW HANDLER
  // ============================================================
  const handleFlow = (text) => {
    if (step === "ask_item") {
      const item = extractItem(text) || text;
      context.item = item;

      if (!context.location) {
        step = "ask_location";
        botReply(
          `Where did you ${context.intent === "found" ? "find" : "lose"} your ${item}?`,
          SUGGESTIONS.location
        );
      } else {
        step = "ask_time";
        botReply("When did this happen?", SUGGESTIONS.time);
      }
      return true;
    }

    if (step === "ask_location") {
      context.location = extractLocation(text) || text;

      if (!context.time) {
        step = "ask_time";
        botReply("When did this happen?", SUGGESTIONS.time);
      } else {
        step = null;
        deliverSummary();
      }
      return true;
    }

    if (step === "ask_time") {
      context.time = extractTime(text) || text;
      step = null;
      deliverSummary();
      return true;
    }

    return false;
  };

  // ============================================================
  //  11. SUMMARY
  // ============================================================
  const deliverSummary = () => {
    const { intent, item, location, time } = context;
    const action = intent === "found" ? "found" : "lost";

    const summary =
      `Got it! Here's a summary:\n\n` +
      `Action : ${action.toUpperCase()}\n` +
      `Item   : ${item || "Not specified"}\n` +
      `Location: ${location || "Not specified"}\n` +
      `Time   : ${time || "Not specified"}\n\n` +
      `Please go to the ${intent === "found" ? "Found Item" : "Lost Item"} ` +
      `section and submit this report. Your details will help match the item quickly.`;

    botReply(summary, ["Submit Report", "Search Items", "Start Over"]);

    context = { intent: null, item: null, location: null, time: null };
  };

  // ============================================================
  //  12. FREE-FORM RESPONSE FALLBACK
  // ============================================================
  const getFreeResponse = (text, intent) => {
    if (/^(hi|hello|hey|hii+|hry|sup|helloo+|hiii+|heyy+|what's up chat|whats up chat)\b/.test(text))
      return { text: "Hello! How can I help you today?", chips: SUGGESTIONS.welcome };

    if (text.includes("thanks") || text.includes("thank you"))
      return { text: "You're welcome! Anything else I can help with?", chips: SUGGESTIONS.help };

    if (text.includes("bye") || text.includes("goodbye"))
      return { text: "Goodbye! Hope you find/return the item soon.", chips: null };

    if (text.includes("login") || text.includes("sign in"))
      return { text: "Please login to report or track items. Use the Login button on the top right of the homepage.", chips: null };

    if (text.includes("status"))
      return { text: "Check your dashboard for real-time status updates on your reported items.", chips: null };

    if (text.includes("photo") || text.includes("image") || text.includes("picture"))
      return { text: "Yes! You can upload a photo while submitting your report to help identify the item.", chips: null };

    if (text.includes("contact"))
      return { text: "You can contact the finder/owner through the contact details shown on the matched report.", chips: null };

    if (text.includes("safe") || text.includes("privacy") || text.includes("data"))
      return { text: "Your data is secure and only shared with the matched party. We take privacy seriously.", chips: null };

    if (text.includes("start over") || text.includes("reset") || text.includes("restart")) {
      context = { intent: null, item: null, location: null, time: null };
      step = null;
      return { text: "Sure! Let's start fresh. What can I help you with?", chips: SUGGESTIONS.welcome };
    }

    if (text.includes("submit report") || (text.includes("submit") && text.includes("report"))) {
      return {
        text: "I cannot submit report on my own but you can submit it by clicking Report lost item in Student dashboard.",
        chips: ["Report Lost Item", "Report Found Item"]
      };
    }

    if (intent === "lost") {
      if (has(KW.itemImportant, text))
        return { text: "Important item lost! Report it immediately and also contact campus security / college office.", chips: ["Report Now", "Contact Security"] };
      if (has(KW.itemAcademic, text))
        return { text: "Lost an academic item? Check classrooms, library, and submit a lost report with details.", chips: SUGGESTIONS.location };
      return { text: "Sorry to hear that! Let me guide you through reporting it.", chips: null };
    }

    if (intent === "found") {
      if (has(KW.itemImportant, text))
        return { text: "Important item found! Please submit it to the college office/security and report it online.", chips: null };
      return { text: "Great that you found something! Let me help you report it.", chips: null };
    }

    if (intent === "search")
      return { text: "Use the search filters on the website. Filter by item type, location, and date for best results.", chips: null };

    if (intent === "claim")
      return { text: "To claim an item, go to the item's report page and provide proof like description, photo, or ID.", chips: null };

    return {
      text: "I'm not sure about that. You can ask me about lost items, found items, searching, or claiming.",
      chips: SUGGESTIONS.welcome
    };
  };

  // ============================================================
  //  13. MAIN MESSAGE HANDLER
  // ============================================================
  const handleUserMessage = (rawText) => {
    const text = rawText.toLowerCase().trim();
    if (!text) return;

    addMsg(rawText, "user");

    if (handleFlow(text)) return;

    const intent = detectIntent(text);

    const item     = extractItem(text);
    const location = extractLocation(text);
    const time     = extractTime(text);
    if (item)     context.item     = item;
    if (location) context.location = location;
    if (time)     context.time     = time;

    if (intent === "lost" || intent === "found") {
      context.intent = intent;

      if (!context.item) {
        step = "ask_item";
        botReply(
          intent === "lost"
            ? "Sorry to hear that! What item did you lose?"
            : "Good of you to report it! What item did you find?",
          SUGGESTIONS.item
        );
        return;
      }

      if (!context.location) {
        step = "ask_location";
        botReply(
          `Where did you ${intent === "found" ? "find" : "lose"} your ${context.item}?`,
          SUGGESTIONS.location
        );
        return;
      }

      if (!context.time) {
        step = "ask_time";
        botReply("When did this happen?", SUGGESTIONS.time);
        return;
      }

      deliverSummary();
      return;
    }

    const { text: replyText, chips } = getFreeResponse(text, intent);
    botReply(replyText, chips);
  };

  // ============================================================
  //  14. INPUT EVENT LISTENERS
  // ============================================================
  const send = () => {
    const val = inputEl.value.trim();
    if (!val) return;
    inputEl.value = "";
    handleUserMessage(val);
  };

  sendEl.addEventListener("click", send);
  inputEl.addEventListener("keydown", e => { if (e.key === "Enter") send(); });

})();
