console.log("PhishScope: content.js loaded on Gmail.");

// --- Whitelist Check ---
async function isSenderWhitelisted(senderEmail) {
  const data = await chrome.storage.local.get("phishScopeWhitelist");
  const whitelist = data.phishScopeWhitelist || [];
  return whitelist.includes(senderEmail);
}

// --- UI Injection ---
function injectAnalysisUI(element, result) {
  // Remove any old badge
  const oldBadge = element.querySelector("#phishscope-badge");
  if (oldBadge) oldBadge.remove();

  let badgeHTML = "";
  if (result.prediction === "Phishing") {
    // RED (Phishing)
    badgeHTML = `
      <div id="phishscope-badge" style="background: #a82a2a; color: white; padding: 10px; border-radius: 8px; margin-bottom: 15px; font-family: Arial, sans-serif;">
        <strong style="font-size: 16px;">PhishScope Analysis: ${result.prediction} (${(result.confidence * 100).toFixed(0)}%)</strong>
        <p style="margin-top: 8px; font-size: 14px;">${result.reasons.join(" ")}</p>
      </div>
    `;
  } else if (result.whitelisted) {
    // BLUE (Trusted)
    badgeHTML = `
      <div id="phishscope-badge" style="background: #3a5a9e; color: white; padding: 8px; border-radius: 8px; margin-bottom: 15px; font-family: Arial, sans-serif;">
        <strong style="font-size: 14px;">PhishScope: Sender is on your Trusted List.</strong>
      </div>
    `;
  } else {
    // GREEN (Legitimate)
     badgeHTML = `
      <div id="phishscope-badge" style="background: #2a7e4a; color: white; padding: 8px; border-radius: 8px; margin-bottom: 15px; font-family: Arial, sans-serif;">
        <strong style="font-size: 14px;">PhishScope Analysis: ${result.prediction} (${((1 - result.confidence) * 100).toFixed(0)}% Confidence)</strong>
      </div>
    `;
  }

  // Inject the badge right before the email body
  element.insertAdjacentHTML("beforebegin", badgeHTML);
}

// --- Main Analysis Function ---
async function analyzeEmail(emailElement) {
  // 1. Find the Sender, Subject, and Body
  // NOTE: These selectors are ESTIMATES. Gmail's code is complex.
  const senderEl = emailElement.querySelector('span[email]');
  const subjectEl = emailElement.querySelector('h2.hP');
  // The body is often in a div with the class 'aA'
  const bodyEl = emailElement.querySelector('div.aA, div.aCi'); 

  if (!senderEl || !subjectEl || !bodyEl) {
    console.log("PhishScope: Could not find all email elements (sender, subject, body).");
    return;
  }

  const sender = senderEl.getAttribute('email');
  const subject = subjectEl.innerText;
  const body = bodyEl.innerText;

  // 2. Check Whitelist (Your Feature!)
  if (await isSenderWhitelisted(sender)) {
    console.log("PhishScope: Sender is whitelisted. Skipping analysis.");
    injectAnalysisUI(emailElement, { whitelisted: true });
    return;
  }

  // 3. Send to Backend
  console.log("PhishScope: Sending to backend for analysis...");
  chrome.runtime.sendMessage(
    {
      action: "analyzeEmail",
      data: { sender, subject, body }
    },
    (response) => {
      if (response && response.success) {
        // 4. Inject the Result
        injectAnalysisUI(emailElement, response.result);
      } else {
        console.error("PhishScope: Backend call failed:", response.error);
        injectAnalysisUI(emailElement, { prediction: "Error", confidence: 0, reasons: ["Could not analyze email. Is the backend server running?"]});
      }
    }
  );
}

// --- Automatic Trigger ---
// Gmail loads content dynamically. We must WATCH for new emails to appear.
const observer = new MutationObserver((mutations) => {
  mutations.forEach((mutation) => {
    mutation.addedNodes.forEach((node) => {
      // Check if the added node is an email container
      // This selector (div[role="listitem"]) is an ESTIMATE for an opened email
      if (node.nodeType === 1 && node.querySelector('h2.hP')) {
        const emailElement = node;
        
        // Check if we've already analyzed this
        if (emailElement.dataset.phishscopeAnalyzed) return;
        emailElement.dataset.phishscopeAnalyzed = "true";

        console.log("PhishScope: New email element detected. Starting analysis.");
        analyzeEmail(emailElement);
      }
    });
  });
});

// Start observing the main Gmail content area
// This selector 'div[role="main"]' is an ESTIMATE
const targetNode = document.querySelector('body');
if (targetNode) {
  observer.observe(targetNode, {
    childList: true,
    subtree: true
  });
} else {
  console.error("PhishScope: Could not find target node to observe.");
}
