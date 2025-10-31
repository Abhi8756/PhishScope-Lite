// Listen for a message from content.js
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  // Check if the message is the one we want
  if (request.action === "analyzeEmail") {
    
    // Log what we received
    console.log("PhishScope: Background script received email data:", request.data);

    // Call our local Flask backend (app.py)
    fetch("http://127.0.0.1:5001/predict", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify(request.data),
    })
    .then(response => response.json())
    .then(result => {
      console.log("PhishScope: Received analysis from backend:", result);
      // Send the successful result back to content.js
      sendResponse({ success: true, result: result });
    })
    .catch(error => {
      console.error("PhishScope: Error calling backend:", error);
      // Send the error back to content.js
      sendResponse({ success: false, error: error.message });
    });

    // This is important: return true to indicate we will send a response asynchronously
    return true; 
  }
});