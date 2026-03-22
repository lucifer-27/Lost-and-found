// CampusFind Chatbot Widget (Vanilla JavaScript)
// Implements a modular, self-invoking chatbot component that injects UI elements,
// manages state and user interactions, and delivers rule-based automated responses.

(() => {
  const ROOT_ID = "cf-chatbot-root";
  if (document.getElementById(ROOT_ID)) return;

  const style = document.createElement("style");
  style.textContent = `
#${ROOT_ID} {
  position: fixed;
  right: 20px;
  bottom: 20px;
  z-index: 9999;
  font-family: Arial, sans-serif;
}

#cf-chatbot-toggle {
  width: 54px;
  height: 54px;
  border-radius: 999px;
  background: #007bff;
  color: #fff;
  border: none;
  cursor: pointer;
  box-shadow: 0 10px 25px rgba(0,0,0,0.25);
  display: grid;
  place-items: center;
}

#cf-chatbot-toggle:hover {
  filter: brightness(1.05);
}

#cf-chatbot-panel {
  position: absolute;
  right: 0;
  bottom: 70px;
  width: 320px;
  height: 420px;
  background: #fff;
  border-radius: 12px;
  box-shadow: 0 16px 50px rgba(0,0,0,0.25);
  display: none;
  flex-direction: column;
  overflow: hidden;
}

#cf-chatbot-panel.is-open {
  display: flex;
}

.cf-chatbot-header {
  background: #007bff;
  color: #fff;
  padding: 10px 12px;
  display: flex;
  align-items: center;
  justify-content: space-between;
  font-weight: 600;
}

.cf-chatbot-close {
  background: rgba(255,255,255,0.15);
  color: #fff;
  border: none;
  padding: 6px 10px;
  border-radius: 8px;
  cursor: pointer;
  font-size: 12px;
}

.cf-chatbot-body {
  flex: 1;
  padding: 10px;
  overflow-y: auto;
  background: #f7f7f7;
}

.cf-chatbot-message {
  margin: 8px 0;
  padding: 8px 10px;
  border-radius: 8px;
  max-width: 85%;
  font-size: 14px;
  line-height: 1.4;
}

.cf-chatbot-user {
  background: #dcf8c6;
  margin-left: auto;
}

.cf-chatbot-bot {
  background: #e9e9e9;
  margin-right: auto;
}

.cf-chatbot-input {
  display: flex;
  border-top: 1px solid #ddd;
  background: #fff;
}

.cf-chatbot-input input {
  flex: 1;
  padding: 10px;
  border: none;
  outline: none;
  font-size: 14px;
}

.cf-chatbot-input button {
  padding: 10px 12px;
  background: #007bff;
  color: #fff;
  border: none;
  cursor: pointer;
}

@media (max-width: 480px) {
  #cf-chatbot-panel {
    width: calc(100vw - 32px);
    right: 16px;
    height: 70vh;
  }
}
  `.trim();
  document.head.appendChild(style);

  const root = document.createElement("div");
  root.id = ROOT_ID;
  root.innerHTML = `
    <button id="cf-chatbot-toggle" aria-expanded="false" aria-controls="cf-chatbot-panel" title="Chat with us">
      <svg width="26" height="26" viewBox="0 0 24 24" fill="none" aria-hidden="true">
        <path d="M7 9h10M7 13h6" stroke="currentColor" stroke-width="2" stroke-linecap="round"/>
        <path d="M20 12a8 8 0 1 1-3.2-6.4L20 5v7Z" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/>
      </svg>
    </button>
    <div id="cf-chatbot-panel" role="dialog" aria-label="Chatbot">
      <div class="cf-chatbot-header">
        <span>Help Chatbot</span>
        <button class="cf-chatbot-close" id="cf-chatbot-close" type="button">Back</button>
      </div>
      <div class="cf-chatbot-body" id="cf-chatbot-body"></div>
      <div class="cf-chatbot-input">
        <input type="text" id="cf-chatbot-input" placeholder="Ask something..." />
        <button type="button" id="cf-chatbot-send">Send</button>
      </div>
    </div>
  `;
  document.body.appendChild(root);

  const panel = document.getElementById("cf-chatbot-panel");
  const toggle = document.getElementById("cf-chatbot-toggle");
  const closeBtn = document.getElementById("cf-chatbot-close");
  const body = document.getElementById("cf-chatbot-body");
  const input = document.getElementById("cf-chatbot-input");
  const sendBtn = document.getElementById("cf-chatbot-send");

  const openPanel = () => {
    panel.classList.add("is-open");
    toggle.setAttribute("aria-expanded", "true");
    input.focus();
  };

  const closePanel = () => {
    panel.classList.remove("is-open");
    toggle.setAttribute("aria-expanded", "false");
  };

  toggle.addEventListener("click", () => {
    if (panel.classList.contains("is-open")) closePanel();
    else openPanel();
  });

  closeBtn.addEventListener("click", closePanel);

  const addMessage = (message, className) => {
    const msgDiv = document.createElement("div");
    msgDiv.className = `cf-chatbot-message ${className}`;
    msgDiv.innerText = message;
    body.appendChild(msgDiv);
    body.scrollTop = body.scrollHeight;
  };

  const getBotResponse = (inputText) => {
    const text = inputText.toLowerCase();
    if (text.includes("login")) {
      return "You can find the login button on the top right corner of the homepage.";
    }
    if (text.includes("lost item")) {
      return "Go to the report section and select 'Lost Item', then fill the form.";
    }
    if (text.includes("found item")) {
      return "Go to the report section and select 'Found Item', then submit the details.";
    }
    if (text.includes("view") || text.includes("found items")) {
      return "You can view found items in the 'Found Items' section on the website.";
    }
    if (text.includes("match")) {
      return "The system matches lost and found items based on item details like name, color, and location.";
    }
    return "Sorry, I didn't understand. Please try asking in a different way.";
  };

  const sendMessage = () => {
    const userText = input.value.trim();
    if (!userText) return;
    addMessage(userText, "cf-chatbot-user");
    input.value = "";

    const botReply = getBotResponse(userText);
    setTimeout(() => addMessage(botReply, "cf-chatbot-bot"), 350);
  };

  sendBtn.addEventListener("click", sendMessage);
  input.addEventListener("keydown", (e) => {
    if (e.key === "Enter") sendMessage();
  });
})();
