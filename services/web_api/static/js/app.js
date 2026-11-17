/**
 * AI-IDS/IPS Client-side Application Scripts
 * Manages live UTC clock, CSRF helpers, and UI notifications.
 */

document.addEventListener("DOMContentLoaded", () => {
    initClock();
    initFlashAlerts();
});

/**
 * Updates top navigation bar with high-precision UTC time.
 */
function initClock() {
    const clockEl = document.getElementById("utc-clock");
    if (!clockEl) return;

    function update() {
        const now = new Date();
        const iso = now.toISOString().replace("T", " ").replace("Z", " UTC");
        clockEl.textContent = iso;
    }
    update();
    setInterval(update, 1000);
}

/**
 * Configures dismissible flash alerts.
 */
function initFlashAlerts() {
    document.querySelectorAll(".flash-alert").forEach((alert) => {
        const closeBtn = alert.querySelector(".flash-close");
        if (closeBtn) {
            closeBtn.addEventListener("click", () => {
                alert.style.opacity = "0";
                setTimeout(() => alert.remove(), 200);
            });
        }
    });
}

/**
 * Helper to fetch CSRF token from page meta tag.
 */
function getCsrfToken() {
    const meta = document.querySelector('meta[name="csrf-token"]');
    return meta ? meta.getAttribute("content") : "";
}

/**
 * Copy text to clipboard with feedback pill.
 */
async function copyToClipboard(text, btnElement) {
    try {
        await navigator.clipboard.writeText(text);
        if (btnElement) {
            const original = btnElement.textContent;
            btnElement.textContent = "Copied!";
            setTimeout(() => {
                btnElement.textContent = original;
            }, 2000);
        }
    } catch (err) {
        console.error("Clipboard copy failed:", err);
    }
}
