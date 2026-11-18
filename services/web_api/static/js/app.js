/**
 * AI-IDS/IPS Client-side Application Scripts
 *
 * This file is loaded as an external asset and is compatible with the strict
 * nonce-based Content-Security-Policy (no inline scripts or inline handlers).
 * It adds behavior through data-* attributes only.
 */

"use strict";

document.addEventListener("DOMContentLoaded", () => {
    initClock();
    initFlashAlerts();
    initNavToggle();
    initCopyButtons();
    initConfirmForms();
});

/**
 * Updates the top navigation bar with the current UTC time.
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
    document.querySelectorAll("[data-dismiss-flash]").forEach((button) => {
        button.addEventListener("click", () => {
            const alert = button.closest(".flash-alert");
            if (!alert) return;
            alert.classList.add("is-dismissed");
            window.setTimeout(() => alert.remove(), 200);
        });
    });
}

/**
 * Mobile off-canvas navigation.
 */
function initNavToggle() {
    const toggle = document.querySelector("[data-nav-toggle]");
    const backdrop = document.querySelector("[data-nav-close]");
    if (!toggle) return;

    function setOpen(open) {
        document.body.classList.toggle("nav-open", open);
        toggle.setAttribute("aria-expanded", open ? "true" : "false");
        if (backdrop) {
            backdrop.hidden = !open;
        }
    }

    toggle.addEventListener("click", () => {
        setOpen(!document.body.classList.contains("nav-open"));
    });

    if (backdrop) {
        backdrop.addEventListener("click", () => setOpen(false));
    }

    document.querySelectorAll(".soc-sidebar .nav-link").forEach((link) => {
        link.addEventListener("click", () => setOpen(false));
    });

    document.addEventListener("keydown", (event) => {
        if (event.key === "Escape") {
            setOpen(false);
        }
    });
}

/**
 * Copy-to-clipboard buttons.
 *
 * Usage:
 *   <button data-copy="literal text" data-copy-label="Copy">Copy</button>
 *   <button data-copy-target="element-id" data-copy-label="Copy all">Copy</button>
 */
function initCopyButtons() {
    const buttons = document.querySelectorAll("[data-copy], [data-copy-target]");
    buttons.forEach((button) => {
        button.addEventListener("click", async () => {
            let text = button.getAttribute("data-copy") || "";
            const targetId = button.getAttribute("data-copy-target");
            if (targetId) {
                const target = document.getElementById(targetId);
                text = target ? target.textContent || "" : "";
            }
            if (!text) return;

            const label = button.getAttribute("data-copy-label") || "Copy";
            try {
                await copyText(text);
                flashButtonLabel(button, "Copied!", label);
            } catch (error) {
                console.error("Clipboard copy failed:", error);
                flashButtonLabel(button, "Copy failed", label);
            }
        });
    });
}

async function copyText(text) {
    if (navigator.clipboard && window.isSecureContext) {
        await navigator.clipboard.writeText(text);
        return;
    }

    // Fallback for non-secure contexts (e.g. local HTTP development).
    const area = document.createElement("textarea");
    area.value = text;
    area.setAttribute("readonly", "");
    area.classList.add("visually-hidden");
    document.body.appendChild(area);
    area.select();
    try {
        const ok = document.execCommand("copy");
        if (!ok) throw new Error("execCommand copy returned false");
    } finally {
        document.body.removeChild(area);
    }
}

function flashButtonLabel(button, temporary, original) {
    button.textContent = temporary;
    window.setTimeout(() => {
        button.textContent = original;
    }, 2000);
}

/**
 * Confirmation prompts for destructive forms (data-confirm attribute).
 */
function initConfirmForms() {
    document.querySelectorAll("form[data-confirm]").forEach((form) => {
        form.addEventListener("submit", (event) => {
            const message = form.getAttribute("data-confirm");
            if (message && !window.confirm(message)) {
                event.preventDefault();
            }
        });
    });
}

/**
 * Reads the CSRF token injected into the page meta tag.
 */
function getCsrfToken() {
    const meta = document.querySelector('meta[name="csrf-token"]');
    return meta ? meta.getAttribute("content") || "" : "";
}

/**
 * Fetch wrapper for JSON/AJAX requests.
 *
 * State-changing requests receive the CSRF token in the X-CSRFToken header,
 * which Flask-WTF accepts alongside the form field.
 */
async function apiFetch(url, options = {}) {
    const headers = new Headers(options.headers || {});
    const method = (options.method || "GET").toUpperCase();
    if (!["GET", "HEAD", "OPTIONS"].includes(method)) {
        const token = getCsrfToken();
        if (token) {
            headers.set("X-CSRFToken", token);
        }
    }
    if (!headers.has("Accept")) {
        headers.set("Accept", "application/json");
    }
    if (options.body && typeof options.body === "string" && !headers.has("Content-Type")) {
        headers.set("Content-Type", "application/json");
    }
    return fetch(url, {
        ...options,
        method,
        headers,
        credentials: "same-origin",
    });
}

// Expose for future modules that need authenticated AJAX calls.
window.apiFetch = apiFetch;
window.getCsrfToken = getCsrfToken;
