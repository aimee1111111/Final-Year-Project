/*
  This script controls the front-end behaviour of the URL checking feature.

  It waits for the page to load, connects the main buttons and input fields,
  allows the user to open or hide the URL input area, clear the entered URL,
  and submit a URL for scanning. When the user submits a link, the script
  sends it to multiple checking services at the same time and then displays
  the combined result on the page. If something goes wrong, it shows an
  error message instead.
*/

import {
  checkGoogleSafeBrowsing,
  checkVirusTotal,
  checkPhishAPIBackend,
  checkPhishStats,
  checkDnsHealth
} from "./url-services.js";

import { displayCombinedResults, displayUrlError } from "./url-display.js";

document.addEventListener("DOMContentLoaded", () => {
  // Main button used to show or hide the URL checker input area
  const urlButton = document.getElementById("urlButton");

  // Container holding the URL input box and related controls
  const urlInputBox = document.getElementById("urlInputBox");

  // Button that submits the entered URL for scanning
  const submitUrl = document.getElementById("submitUrl");

  // Button that clears the input and any shown results
  const clearUrl = document.getElementById("clearUrl");

  // Area where loading text, results, or errors are displayed
  const resultMessage = document.getElementById("resultMessage");

  // Text input where the user enters the URL
  const urlInput = document.getElementById("urlInput");

  // Stops the script if required page elements are missing
  if (!urlButton || !urlInputBox || !submitUrl || !resultMessage || !urlInput) {
    console.warn("url-checker.js: required elements missing on this page.");
    return;
  }

  urlButton.addEventListener("click", () => {
    // Checks whether the input box is currently hidden
    const isHidden =
      urlInputBox.style.display === "none" || !urlInputBox.style.display;

    // Toggles the input box visibility
    urlInputBox.style.display = isHidden ? "block" : "none";

    // Updates accessibility state for screen readers
    urlButton.setAttribute("aria-expanded", String(isHidden));

    // Places the cursor into the input field when opened
    if (isHidden) urlInput.focus();
  });

  clearUrl.addEventListener("click", () => {
    // Clears the entered URL
    urlInput.value = "";

    // Removes any result text from the page
    resultMessage.innerHTML = "";

    // Resets any custom text colour
    resultMessage.style.color = "";

    // Places the cursor back into the input field
    urlInput.focus();
  });

  submitUrl.addEventListener("click", async () => {
    // Gets the URL entered by the user and removes extra spaces
    const url = (urlInput.value || "").trim();

    // Stops if the input is empty
    if (!url) {
      alert("Please enter a URL.");
      return;
    }

    // Shows a loading message while checks are running
    resultMessage.innerHTML =
      "🔍 Checking URL safety with multiple services...<br><small>This may take a few seconds</small>";
    resultMessage.style.color = "orange";

    // Disables the submit button to prevent repeated clicks
    submitUrl.disabled = true;

    // Records the start time so total scan time can be shown later
    const startTime = Date.now();

    try {
      // Sends the URL to all checking services at the same time
      const results = await Promise.all([
        checkGoogleSafeBrowsing(url),
        checkVirusTotal(url),
        checkPhishAPIBackend(url),
        checkPhishStats(url),
        checkDnsHealth(url)
      ]);

      // Calculates how long the scan took
      const scanTime = ((Date.now() - startTime) / 1000).toFixed(1);

      // Displays the combined scan results on the page
      displayCombinedResults(results, scanTime, url);
    } catch (err) {
      // Logs the error for debugging
      console.error("Error checking URL:", err);

      // Shows a user-friendly error message
      displayUrlError(resultMessage);
    } finally {
      // Re-enables the submit button whether the scan succeeded or failed
      submitUrl.disabled = false;
    }
  });
});