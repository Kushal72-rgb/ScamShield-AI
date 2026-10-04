// ScamShield AI Frontend Controller

const PRESET_MESSAGES = {
  bank: "URGENT from Chase Bank: Your account has been temporarily locked due to 3 unauthorized transaction attempts of $489.99. Click immediately to restore access and verify your debit card: http://chase-security-restore.info/auth",
  delivery: "USPS Alert: We have an undeliverable package #US940550000 awaiting confirmation. Please update your delivery address and pay the $1.85 redelivery charge within 24 hours at http://usps-redelivery-tracking.cc to avoid return to sender.",
  lottery: "CONGRATULATIONS! Your mobile number was selected as the lucky winner of $750,000 in the Global Tech Foundation Grant. To process your payout, reply with your full legal name, ID copy, and wire $120 for courier fees.",
  safe: "Hey Alex, mom mentioned you left your winter coat at her house yesterday. I can bring it by your apartment on Thursday after work if you'll be around."
};

const CONVERSATION_PRESETS = {
  pig_butchering: [
    { sender: "Stranger", message: "Hi Anna! Are we still meeting for lunch at the cafe tomorrow?" },
    { sender: "You", message: "Sorry, I think you have the wrong number. I'm not Anna." },
    { sender: "Stranger", message: "Oh I'm so embarrassed! My assistant must have typed the number wrong. But you seem so polite! I'm Lisa, currently visiting from London. What's your name?" },
    { sender: "Stranger", message: "I actually trade crypto commodities on the side. I gained $4,200 just yesterday on this exclusive staking pool! Check out my mentor's portal if you want to try: https://eth-yield-global.top/stake" }
  ],
  tech_support: [
    { sender: "System Alert", message: "MICROSOFT CRITICAL WARNING: Trojan virus #0x80244007 detected on your machine! Do not turn off your computer. Call Microsoft Support immediately: 1-800-555-0199." },
    { sender: "Support Agent", message: "Hello, this is Agent Davis from Microsoft Security Department. We see foreign IP connections downloading your financial passwords right now." },
    { sender: "Support Agent", message: "To secure your account and clear the network block, go to Target or Walmart and purchase two $100 Google Play security cards, then read me the 16-digit PIN numbers over the phone." }
  ],
  distress: [
    { sender: "Unknown Number", message: "Dad! My phone was stolen and smashed at the train station. This is my friend's phone, please save it." },
    { sender: "You", message: "Are you okay?! Where are you right now?" },
    { sender: "Unknown Number", message: "I'm stranded and the clinic needs an emergency deposit of $400 for treatment or they won't help. Can you please Apple Pay or Zelle $400 to 9876543210 right now? Urgent!!" }
  ]
};

// State
let selectedImageFile = null;
let currentMode = "text";
let conversationTurns = [
  { sender: "Stranger", message: "" },
  { sender: "You", message: "" }
];

// DOM Elements - Text Mode
const messageInput = document.getElementById("messageInput");
const charCount = document.getElementById("charCount");
const analyzeForm = document.getElementById("analyzeForm");
const submitBtn = document.getElementById("submitBtn");
const btnText = submitBtn.querySelector(".btn-text");
const btnSpinner = submitBtn.querySelector(".btn-spinner");
const clearBtn = document.getElementById("clearBtn");
const retryBtn = document.getElementById("retryBtn");
const apiKeyBanner = document.getElementById("apiKeyBanner");

// DOM Elements - Mode Switcher
const tabText = document.getElementById("tabText");
const tabImage = document.getElementById("tabImage");
const tabConversation = document.getElementById("tabConversation");
const textModeContainer = document.getElementById("textModeContainer");
const imageModeContainer = document.getElementById("imageModeContainer");
const conversationModeContainer = document.getElementById("conversationModeContainer");

// DOM Elements - Image Mode (Phase 4)
const dropZone = document.getElementById("dropZone");
const imageFileInput = document.getElementById("imageFileInput");
const imagePreviewContainer = document.getElementById("imagePreviewContainer");
const imagePreviewImg = document.getElementById("imagePreviewImg");
const previewFileName = document.getElementById("previewFileName");
const previewFileSize = document.getElementById("previewFileSize");
const removeImageBtn = document.getElementById("removeImageBtn");
const clearImageBtn = document.getElementById("clearImageBtn");
const submitImageBtn = document.getElementById("submitImageBtn");
const submitImageBtnText = submitImageBtn ? submitImageBtn.querySelector(".btn-text") : null;
const submitImageBtnSpinner = submitImageBtn ? submitImageBtn.querySelector(".btn-spinner") : null;
const loadSampleImageBtn = document.getElementById("loadSampleImageBtn");

// DOM Elements - Conversation Mode (Phase 7)
const conversationTurnsList = document.getElementById("conversationTurnsList");
const addTurnBtn = document.getElementById("addTurnBtn");
const clearConversationBtn = document.getElementById("clearConversationBtn");
const submitConversationBtn = document.getElementById("submitConversationBtn");
const submitConversationBtnText = submitConversationBtn ? submitConversationBtn.querySelector(".btn-text") : null;
const submitConversationBtnSpinner = submitConversationBtn ? submitConversationBtn.querySelector(".btn-spinner") : null;

// State Containers
const idleState = document.getElementById("idleState");
const loadingState = document.getElementById("loadingState");
const errorState = document.getElementById("errorState");
const errorMessage = document.getElementById("errorMessage");
const resultContent = document.getElementById("resultContent");

// Result Elements
const riskBanner = document.getElementById("riskBanner");
const riskBadge = document.getElementById("riskBadge");
const categoryBadge = document.getElementById("categoryBadge");
const explanationText = document.getElementById("explanationText");
const indicatorsList = document.getElementById("indicatorsList");
const actionText = document.getElementById("actionText");
const urlAnalysisBlock = document.getElementById("urlAnalysisBlock");
const urlsList = document.getElementById("urlsList");
const reputationBlock = document.getElementById("reputationBlock");
const reputationList = document.getElementById("reputationList");

// Evidence Summary Elements (Phase 6)
const evidenceSummaryBlock = document.getElementById("evidenceSummaryBlock");
const evidenceGemini = document.getElementById("evidenceGemini");
const evidenceLocalUrl = document.getElementById("evidenceLocalUrl");
const evidencePhishTank = document.getElementById("evidencePhishTank");
const evidenceRationale = document.getElementById("evidenceRationale");
const confidenceRow = document.getElementById("confidenceRow");
const evidenceConfidence = document.getElementById("evidenceConfidence");

// Conversation Tactics Elements (Phase 7)
const conversationTacticsBlock = document.getElementById("conversationTacticsBlock");
const tacticTrustBadge = document.getElementById("tacticTrustBadge");
const tacticUrgencyBadge = document.getElementById("tacticUrgencyBadge");
const tacticPaymentBadge = document.getElementById("tacticPaymentBadge");
const groomingPatternRow = document.getElementById("groomingPatternRow");
const groomingPatternText = document.getElementById("groomingPatternText");

// Initialize
document.addEventListener("DOMContentLoaded", () => {
  checkBackendHealth();
  setupEventListeners();
  renderConversationTurns();
});

function setupEventListeners() {
  // Mode Tabs Switching
  if (tabText) tabText.addEventListener("click", () => switchMode("text"));
  if (tabImage) tabImage.addEventListener("click", () => switchMode("image"));
  if (tabConversation) tabConversation.addEventListener("click", () => switchMode("conversation"));

  // Text Mode Listeners
  if (messageInput) {
    messageInput.addEventListener("input", updateCharCount);
  }

  // Text Preset chips
  document.querySelectorAll(".chip-btn[data-preset]").forEach(btn => {
    btn.addEventListener("click", () => {
      const presetKey = btn.dataset.preset;
      if (PRESET_MESSAGES[presetKey]) {
        switchMode("text");
        messageInput.value = PRESET_MESSAGES[presetKey];
        updateCharCount();
        messageInput.focus();
      }
    });
  });

  // Conversation Preset chips
  document.querySelectorAll(".chip-btn[data-conv-preset]").forEach(btn => {
    btn.addEventListener("click", () => {
      const presetKey = btn.dataset.convPreset;
      loadConversationPreset(presetKey);
    });
  });

  // Clear text button
  if (clearBtn) {
    clearBtn.addEventListener("click", () => {
      messageInput.value = "";
      updateCharCount();
      showState("idle");
      messageInput.focus();
    });
  }

  // Form submit for Text
  if (analyzeForm) {
    analyzeForm.addEventListener("submit", (e) => {
      e.preventDefault();
      handleAnalysis();
    });
  }

  // Conversation Mode Buttons
  if (addTurnBtn) {
    addTurnBtn.addEventListener("click", () => addConversationTurn());
  }
  if (clearConversationBtn) {
    clearConversationBtn.addEventListener("click", clearConversation);
  }
  if (submitConversationBtn) {
    submitConversationBtn.addEventListener("click", handleConversationAnalysis);
  }

  // Image Mode Listeners (Phase 4)
  if (dropZone && imageFileInput) {
    // Click dropzone to open file dialog
    dropZone.addEventListener("click", () => imageFileInput.click());

    // File input changed
    imageFileInput.addEventListener("change", (e) => {
      if (e.target.files && e.target.files[0]) {
        handleFileSelection(e.target.files[0]);
      }
    });

    // Drag & Drop events
    dropZone.addEventListener("dragover", (e) => {
      e.preventDefault();
      dropZone.classList.add("dragover");
    });

    dropZone.addEventListener("dragleave", () => {
      dropZone.classList.remove("dragover");
    });

    dropZone.addEventListener("drop", (e) => {
      e.preventDefault();
      dropZone.classList.remove("dragover");
      if (e.dataTransfer.files && e.dataTransfer.files[0]) {
        handleFileSelection(e.dataTransfer.files[0]);
      }
    });
  }

  // Remove / Clear image buttons
  if (removeImageBtn) {
    removeImageBtn.addEventListener("click", clearSelectedImage);
  }
  if (clearImageBtn) {
    clearImageBtn.addEventListener("click", () => {
      clearSelectedImage();
      showState("idle");
    });
  }

  // Submit image button
  if (submitImageBtn) {
    submitImageBtn.addEventListener("click", handleImageAnalysis);
  }

  // Load sample scam screenshot button
  if (loadSampleImageBtn) {
    loadSampleImageBtn.addEventListener("click", loadSampleScreenshot);
  }

  // Retry button
  if (retryBtn) {
    retryBtn.addEventListener("click", () => {
      if (currentMode === "text" && messageInput.value.trim()) {
        handleAnalysis();
      } else if (currentMode === "image" && selectedImageFile) {
        handleImageAnalysis();
      } else if (currentMode === "conversation" && conversationTurns.some(t => t.message.trim())) {
        handleConversationAnalysis();
      } else {
        showState("idle");
      }
    });
  }
}

function switchMode(mode) {
  currentMode = mode;
  if (tabText) tabText.classList.toggle("active", mode === "text");
  if (tabImage) tabImage.classList.toggle("active", mode === "image");
  if (tabConversation) tabConversation.classList.toggle("active", mode === "conversation");

  if (textModeContainer) textModeContainer.classList.toggle("hidden", mode !== "text");
  if (imageModeContainer) imageModeContainer.classList.toggle("hidden", mode !== "image");
  if (conversationModeContainer) conversationModeContainer.classList.toggle("hidden", mode !== "conversation");

  if (mode === "text" && messageInput) messageInput.focus();
}

function handleFileSelection(file) {
  const validTypes = ["image/png", "image/jpeg", "image/jpg", "image/webp"];
  if (!validTypes.includes(file.type.toLowerCase())) {
    alert("Please select a supported image file (PNG, JPG, or WEBP).");
    return;
  }

  if (file.size > 10 * 1024 * 1024) {
    alert("File size exceeds 10MB limit. Please choose a smaller image.");
    return;
  }

  selectedImageFile = file;

  // Render preview
  const reader = new FileReader();
  reader.onload = (e) => {
    imagePreviewImg.src = e.target.result;
    previewFileName.textContent = file.name;
    previewFileSize.textContent = formatBytes(file.size);
    imagePreviewContainer.classList.remove("hidden");
    dropZone.classList.add("hidden");
    submitImageBtn.disabled = false;
  };
  reader.readAsDataURL(file);
}

function clearSelectedImage() {
  selectedImageFile = null;
  imageFileInput.value = "";
  imagePreviewImg.src = "";
  imagePreviewContainer.classList.add("hidden");
  dropZone.classList.remove("hidden");
  submitImageBtn.disabled = true;
}

async function loadSampleScreenshot() {
  try {
    const res = await fetch("/static/sample_scam_screenshot.png");
    if (!res.ok) throw new Error("Could not load sample image");
    const blob = await res.blob();
    const file = new File([blob], "chase_fraud_alert_screenshot.png", { type: "image/png" });
    handleFileSelection(file);
  } catch (err) {
    console.error("Failed to load sample screenshot", err);
    alert("Could not load sample screenshot.");
  }
}

function formatBytes(bytes) {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
}

function updateCharCount() {
  const length = messageInput.value.length;
  charCount.textContent = `${length} / 5000`;
}

async function checkBackendHealth() {
  try {
    const res = await fetch("/api/health");
    if (res.ok) {
      const data = await res.json();
      if (!data.api_key_configured && apiKeyBanner) {
        apiKeyBanner.classList.remove("hidden");
      } else if (apiKeyBanner) {
        apiKeyBanner.classList.add("hidden");
      }
    }
  } catch (err) {
    console.warn("Could not reach backend health check endpoint", err);
  }
}

function showState(state) {
  idleState.classList.add("hidden");
  loadingState.classList.add("hidden");
  errorState.classList.add("hidden");
  resultContent.classList.add("hidden");

  if (state === "idle") idleState.classList.remove("hidden");
  if (state === "loading") loadingState.classList.remove("hidden");
  if (state === "error") errorState.classList.remove("hidden");
  if (state === "result") resultContent.classList.remove("hidden");
}

function setTextLoading(isLoading) {
  submitBtn.disabled = isLoading;
  if (isLoading) {
    btnText.classList.add("hidden");
    btnSpinner.classList.remove("hidden");
  } else {
    btnText.classList.remove("hidden");
    btnSpinner.classList.add("hidden");
  }
}

function setImageLoading(isLoading) {
  submitImageBtn.disabled = isLoading;
  if (isLoading) {
    submitImageBtnText.classList.add("hidden");
    submitImageBtnSpinner.classList.remove("hidden");
  } else {
    submitImageBtnText.classList.remove("hidden");
    submitImageBtnSpinner.classList.add("hidden");
  }
}

function setConversationLoading(isLoading) {
  if (!submitConversationBtn) return;
  submitConversationBtn.disabled = isLoading;
  if (isLoading) {
    if (submitConversationBtnText) submitConversationBtnText.classList.add("hidden");
    if (submitConversationBtnSpinner) submitConversationBtnSpinner.classList.remove("hidden");
  } else {
    if (submitConversationBtnText) submitConversationBtnText.classList.remove("hidden");
    if (submitConversationBtnSpinner) submitConversationBtnSpinner.classList.add("hidden");
  }
}

function renderConversationTurns() {
  if (!conversationTurnsList) return;
  conversationTurnsList.innerHTML = "";

  const senderOptions = ["Stranger", "Potential Victim", "Support Agent", "Bank Official", "Unknown Number", "Other"];

  conversationTurns.forEach((turn, idx) => {
    const card = document.createElement("div");
    card.className = "conversation-turn-card";

    const senderSelectHtml = `
      <select class="turn-sender-select" data-index="${idx}">
        ${senderOptions.map(opt => `<option value="${escapeHtml(opt)}" ${turn.sender === opt ? "selected" : ""}>${escapeHtml(opt)}</option>`).join("")}
      </select>
    `;

    card.innerHTML = `
      <div class="turn-header">
        <span class="turn-number">Turn #${idx + 1}</span>
        <div class="turn-actions">
          ${senderSelectHtml}
          ${conversationTurns.length > 1 ? `<button type="button" class="btn-remove-turn" data-index="${idx}" title="Remove this turn">&times;</button>` : ""}
        </div>
      </div>
      <textarea class="turn-input" data-index="${idx}" rows="2" placeholder="Enter message text for this turn...">${escapeHtml(turn.message)}</textarea>
    `;

    conversationTurnsList.appendChild(card);
  });

  // Attach dynamic event listeners to turn inputs
  conversationTurnsList.querySelectorAll(".turn-sender-select").forEach(select => {
    select.addEventListener("change", (e) => {
      const idx = parseInt(e.target.dataset.index, 10);
      if (conversationTurns[idx]) {
        conversationTurns[idx].sender = e.target.value;
      }
    });
  });

  conversationTurnsList.querySelectorAll(".turn-input").forEach(textarea => {
    textarea.addEventListener("input", (e) => {
      const idx = parseInt(e.target.dataset.index, 10);
      if (conversationTurns[idx]) {
        conversationTurns[idx].message = e.target.value;
      }
    });
  });

  conversationTurnsList.querySelectorAll(".btn-remove-turn").forEach(btn => {
    btn.addEventListener("click", (e) => {
      const idx = parseInt(e.target.dataset.index, 10);
      removeConversationTurn(idx);
    });
  });
}

function addConversationTurn(sender = "Stranger", message = "") {
  conversationTurns.push({ sender, message });
  renderConversationTurns();
  // Focus the newly added turn textarea
  const textareas = conversationTurnsList.querySelectorAll(".turn-input");
  if (textareas.length > 0) {
    textareas[textareas.length - 1].focus();
  }
}

function removeConversationTurn(index) {
  if (conversationTurns.length <= 1) return;
  conversationTurns.splice(index, 1);
  renderConversationTurns();
}

function clearConversation() {
  conversationTurns = [
    { sender: "Stranger", message: "" },
    { sender: "Potential Victim", message: "" }
  ];
  renderConversationTurns();
  showState("idle");
}

function loadConversationPreset(presetKey) {
  if (!CONVERSATION_PRESETS[presetKey]) return;
  switchMode("conversation");
  conversationTurns = CONVERSATION_PRESETS[presetKey].map(t => ({ ...t }));
  renderConversationTurns();
}

async function handleConversationAnalysis() {
  const activeTurns = conversationTurns
    .map(t => ({ sender: t.sender.trim() || "Speaker", message: t.message.trim() }))
    .filter(t => t.message.length > 0);

  if (activeTurns.length === 0) {
    alert("Please enter at least one message turn in the conversation thread.");
    return;
  }

  setConversationLoading(true);
  showState("loading");

  try {
    const response = await fetch("/api/analyze-conversation", {
      method: "POST",
      headers: {
        "Content-Type": "application/json"
      },
      body: JSON.stringify({ messages: activeTurns })
    });

    const data = await response.json();

    if (!response.ok) {
      throw new Error(data.detail || "Conversation analysis failed.");
    }

    renderResults(data);
    showState("result");
  } catch (error) {
    console.error("Conversation Analysis Error:", error);
    errorMessage.textContent = error.message || "An unexpected error occurred during conversation analysis.";
    showState("error");
  } finally {
    setConversationLoading(false);
  }
}

async function handleAnalysis() {
  const text = messageInput.value.trim();
  if (!text) {
    messageInput.focus();
    return;
  }

  setTextLoading(true);
  showState("loading");

  try {
    const response = await fetch("/api/analyze", {
      method: "POST",
      headers: {
        "Content-Type": "application/json"
      },
      body: JSON.stringify({ message: text })
    });

    const data = await response.json();

    if (!response.ok) {
      throw new Error(data.detail || "Analysis request failed.");
    }

    renderResults(data);
    showState("result");
  } catch (error) {
    console.error("Analysis Error:", error);
    errorMessage.textContent = error.message || "An unexpected error occurred during analysis.";
    showState("error");
  } finally {
    setTextLoading(false);
  }
}

async function handleImageAnalysis() {
  if (!selectedImageFile) {
    alert("Please select or drop a screenshot first.");
    return;
  }

  setImageLoading(true);
  showState("loading");

  const formData = new FormData();
  formData.append("file", selectedImageFile);

  try {
    const response = await fetch("/api/analyze-image", {
      method: "POST",
      body: formData
    });

    const data = await response.json();

    if (!response.ok) {
      throw new Error(data.detail || "Screenshot analysis failed.");
    }

    renderResults(data);
    showState("result");
  } catch (error) {
    console.error("Screenshot Analysis Error:", error);
    errorMessage.textContent = error.message || "An unexpected error occurred during image analysis.";
    showState("error");
  } finally {
    setImageLoading(false);
  }
}

function renderResults(data) {
  const level = (data.risk_level || "MEDIUM").toUpperCase();

  // Reset theme classes on banner
  riskBanner.className = "risk-banner";

  if (level === "HIGH") {
    riskBanner.classList.add("risk-high-theme");
    riskBadge.textContent = "HIGH RISK";
  } else if (level === "MEDIUM") {
    riskBanner.classList.add("risk-med-theme");
    riskBadge.textContent = "MEDIUM RISK";
  } else {
    riskBanner.classList.add("risk-low-theme");
    riskBadge.textContent = "LOW RISK";
  }

  categoryBadge.textContent = data.scam_category || "Unclassified";
  explanationText.textContent = data.explanation || "No explanation provided.";
  actionText.textContent = data.recommended_action || "Stay vigilant.";

  // Render Multi-Source Evidence Summary (Phase 6)
  if (evidenceSummaryBlock && data.evidence_summary) {
    const es = data.evidence_summary;
    evidenceSummaryBlock.classList.remove("hidden");
    if (evidenceGemini) evidenceGemini.textContent = es.gemini_assessment || "—";
    if (evidenceLocalUrl) evidenceLocalUrl.textContent = es.local_url_findings || "—";
    if (evidencePhishTank) evidencePhishTank.textContent = es.phishtank_findings || "—";
    if (evidenceRationale) evidenceRationale.textContent = es.fusion_rationale || "—";

    if (confidenceRow && evidenceConfidence) {
      if (es.heuristic_confidence) {
        confidenceRow.classList.remove("hidden");
        evidenceConfidence.textContent = es.heuristic_confidence;
      } else {
        confidenceRow.classList.add("hidden");
      }
    }
  } else if (evidenceSummaryBlock) {
    evidenceSummaryBlock.classList.add("hidden");
  }

  // Render indicators
  indicatorsList.innerHTML = "";
  const indicators = Array.isArray(data.suspicious_indicators) ? data.suspicious_indicators : [];

  if (indicators.length === 0) {
    const li = document.createElement("li");
    li.className = "indicator-item";
    li.innerHTML = `
      <span class="indicator-bullet">&#10003;</span>
      <span>No obvious suspicious indicators or deceptive anomalies detected.</span>
    `;
    indicatorsList.appendChild(li);
  } else {
    indicators.forEach(indicator => {
      const li = document.createElement("li");
      li.className = "indicator-item";
      li.innerHTML = `
        <span class="indicator-bullet">
          <svg viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="currentColor" stroke-width="2.5">
            <polyline points="9 18 15 12 9 6"></polyline>
          </svg>
        </span>
        <span>${escapeHtml(indicator)}</span>
      `;
      indicatorsList.appendChild(li);
    });
  }

  // Render URL Security Signals (Phase 2)
  if (urlAnalysisBlock && urlsList) {
    const urls = Array.isArray(data.urls_detected) ? data.urls_detected : [];
    if (urls.length > 0) {
      urlAnalysisBlock.classList.remove("hidden");
      urlsList.innerHTML = "";

      urls.forEach(item => {
        const card = document.createElement("div");
        card.className = `url-card ${item.is_suspicious ? "suspicious" : "clean"}`;

        const protocolBadge = item.is_https
          ? `<span class="url-badge badge-https">HTTPS Encrypted</span>`
          : `<span class="url-badge badge-http">Insecure HTTP</span>`;

        const repBadge = item.is_suspicious
          ? `<span class="url-badge badge-suspicious">Suspicious Domain</span>`
          : `<span class="url-badge badge-legit">Standard Domain</span>`;

        let signalsHtml = "";
        const signals = Array.isArray(item.suspicious_signals) ? item.suspicious_signals : [];
        if (signals.length > 0) {
          signalsHtml = `
            <ul class="url-signals-list">
              ${signals.map(s => `
                <li class="url-signal-item">
                  <span class="url-signal-icon">&#9888;</span>
                  <span>${escapeHtml(s)}</span>
                </li>
              `).join("")}
            </ul>
          `;
        } else {
          signalsHtml = `
            <ul class="url-signals-list">
              <li class="url-signal-item url-signal-clean">
                <span class="url-signal-icon">&#10003;</span>
                <span>No anomalous or deceptive domain patterns flagged locally.</span>
              </li>
            </ul>
          `;
        }

        card.innerHTML = `
          <div class="url-header">
            <span class="url-string">${escapeHtml(item.url)}</span>
            <div class="url-badges">
              ${protocolBadge}
              ${repBadge}
            </div>
          </div>
          <div class="url-meta-row">
            <span>Domain: <strong class="url-domain-tag">${escapeHtml(item.domain)}</strong></span>
          </div>
          ${signalsHtml}
        `;

        urlsList.appendChild(card);
      });
    } else {
      urlAnalysisBlock.classList.add("hidden");
      urlsList.innerHTML = "";
    }
  }

  // Render PhishTank Reputation Evidence (Phase 3 - Separate UI section)
  if (reputationBlock && reputationList) {
    const urls = Array.isArray(data.urls_detected) ? data.urls_detected : [];
    const urlsWithRep = urls.filter(u => u.reputation);

    if (urlsWithRep.length > 0) {
      reputationBlock.classList.remove("hidden");
      reputationList.innerHTML = "";

      urlsWithRep.forEach(item => {
        const rep = item.reputation;
        const repCard = document.createElement("div");

        let statusClass = "status-nomatch";
        let statusBadge = `<span class="url-badge badge-no-match">PhishTank: No Record Found</span>`;
        let alertClass = "";

        if (rep.status === "KNOWN_PHISHING") {
          statusClass = "status-known";
          statusBadge = `<span class="url-badge badge-phishing">&#9888; PhishTank: Confirmed Phishing</span>`;
          alertClass = "alert-red";
        } else if (rep.status === "UNAVAILABLE") {
          statusClass = "status-unavailable";
          statusBadge = `<span class="url-badge badge-unavailable">PhishTank: Lookup Unavailable</span>`;
          alertClass = "alert-gray";
        }

        repCard.className = `reputation-card ${statusClass}`;

        const incidentLink = rep.phish_detail_url
          ? `<a href="${escapeHtml(rep.phish_detail_url)}" target="_blank" rel="noopener noreferrer" class="reputation-link">View Community Evidence &rarr;</a>`
          : "";

        repCard.innerHTML = `
          <div class="reputation-header">
            <span class="reputation-target-url">${escapeHtml(item.url)}</span>
            ${statusBadge}
          </div>
          <div class="reputation-detail-text">
            <strong>Findings:</strong> ${escapeHtml(rep.message)} ${incidentLink}
          </div>
          <div class="reputation-caution-box ${alertClass}">
            <span class="caution-icon">&#9432;</span>
            <span>${escapeHtml(rep.caution_note)}</span>
          </div>
        `;

        reputationList.appendChild(repCard);
      });
    } else {
      reputationBlock.classList.add("hidden");
      reputationList.innerHTML = "";
    }
  }

  // Render Conversation Tactics Block (Phase 7)
  if (conversationTacticsBlock) {
    if (data.conversation_tactics) {
      const ct = data.conversation_tactics;
      conversationTacticsBlock.classList.remove("hidden");

      updateTacticBadge(tacticTrustBadge, ct.trust_building_observed, "Trust Building Observed", "No Trust-Building Detected");
      updateTacticBadge(tacticUrgencyBadge, ct.urgency_escalation_observed, "Escalating Urgency Observed", "Stable / Non-Urgent Tone");
      updateTacticBadge(tacticPaymentBadge, ct.payment_or_credential_demanded, "Payment / Credential Demand Detected", "No Payment / OTP Demand");

      if (ct.grooming_pattern && ct.grooming_pattern.trim()) {
        groomingPatternRow.classList.remove("hidden");
        groomingPatternText.textContent = ct.grooming_pattern;
      } else {
        groomingPatternRow.classList.add("hidden");
      }
    } else {
      conversationTacticsBlock.classList.add("hidden");
    }
  }
}

function updateTacticBadge(element, isActive, activeText, inactiveText) {
  if (!element) return;
  element.className = `tactic-badge ${isActive ? "active" : "inactive"}`;
  element.innerHTML = `${isActive ? "&#9888;" : "&#10003;"} ${isActive ? activeText : inactiveText}`;
}

function escapeHtml(str) {
  if (!str) return "";
  const div = document.createElement("div");
  div.textContent = str;
  return div.innerHTML;
}
