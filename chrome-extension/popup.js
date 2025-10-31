// This script runs when the popup is opened

// Simple function to get the current tab
async function getCurrentTab() {
  let queryOptions = { active: true, currentWindow: true };
  let [tab] = await chrome.tabs.query(queryOptions);
  return tab;
}

// Simple function to find the sender
// THIS IS A MAJOR SIMPLIFICATION. A real app would need
// to message content.js to ask for the sender.
function getSenderFromEmail(emailString) {
  if (!emailString) return null;
  const match = emailString.match(/<(.+?)>/);
  return match ? match[1] : emailString;
}

document.getElementById("trustSender").addEventListener("click", async () => {
  const tab = await getCurrentTab();
  const statusEl = document.getElementById("status");

  if (tab.url.includes("mail.google.com")) {
    // This is a simple, less reliable way to get the sender
    // A more robust way: send a message to content.js and ask for it
    const senderEmail = prompt("Who is the sender you want to trust?\n(e.g., newsletter@company.com)");
    
    if (senderEmail) {
      // 1. Get the current whitelist
      const data = await chrome.storage.local.get("phishScopeWhitelist");
      const whitelist = data.phishScopeWhitelist || [];

      // 2. Add the new sender (if not already there)
      if (!whitelist.includes(senderEmail)) {
        whitelist.push(senderEmail);
        // 3. Save the updated list
        await chrome.storage.local.set({ phishScopeWhitelist: whitelist });
        statusEl.innerText = "Sender added to Trusted List!";
      } else {
        statusEl.innerText = "Sender is already trusted.";
      }
    }
  } else {
    statusEl.innerText = "This only works on mail.google.com";
  }
});
