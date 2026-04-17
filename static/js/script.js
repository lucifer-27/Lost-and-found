// CampusFind Frontend Utility Script
// Provides core interactive functionalities including camera integration, image processing, form validation, UI behavior control, and search filtering
// to support seamless user interaction within the application.

// =============================
// CampusFind Main JavaScript
// =============================

console.log("CampusFind JS Loaded");

// -----------------------------
// Camera Access
// -----------------------------

function startCamera() {

    const video = document.getElementById("video");

    if (!navigator.mediaDevices || !navigator.mediaDevices.getUserMedia) {
        alert("Camera not supported in this browser");
        return;
    }

    navigator.mediaDevices.getUserMedia({ video: true })
        .then(function (stream) {
            video.srcObject = stream;
        })
        .catch(function (error) {
            console.error("Camera error:", error);
            alert("Unable to access camera");
        });
}


// -----------------------------
// Capture Photo
// -----------------------------

function capturePhoto() {

    const video = document.getElementById("video");
    const canvas = document.getElementById("canvas");

    if (!video || !canvas) return;

    const context = canvas.getContext("2d");

    context.drawImage(video, 0, 0, canvas.width, canvas.height);

    const imageData = canvas.toDataURL("image/png");

    const imageInput = document.getElementById("image_data");

    if (imageInput) {
        imageInput.value = imageData;
    }

}


// -----------------------------
// Form Validation
// -----------------------------

function validateRegisterForm() {

    const password = document.getElementById("password");
    const confirm = document.getElementById("confirm_password");

    if (!password || !confirm) return true;

    if (password.value !== confirm.value) {
        alert("Passwords do not match!");
        return false;
    }

    return true;
}


// -----------------------------
// Toggle Password Visibility
// -----------------------------

function togglePassword(id) {

    const input = document.getElementById(id);

    if (!input) return;

    if (input.type === "password") {
        input.type = "text";
    } else {
        input.type = "password";
    }

}

function togglePasswordWithIcon(inputId, openIconId, closedIconId) {

    const input = document.getElementById(inputId);
    const openIcon = document.getElementById(openIconId);
    const closedIcon = document.getElementById(closedIconId);

    if (!input) return;

    const isPasswordHidden = input.type === "password";
    input.type = isPasswordHidden ? "text" : "password";

    if (openIcon && closedIcon) {
        openIcon.classList.toggle("hidden", isPasswordHidden);
        closedIcon.classList.toggle("hidden", !isPasswordHidden);
    }

}

function initRoleDropdowns() {

    const dropdowns = document.querySelectorAll("[data-role-dropdown]");

    dropdowns.forEach(function (dropdown) {

        if (dropdown.dataset.initialized === "true") return;
        dropdown.dataset.initialized = "true";

        const input = dropdown.querySelector("[data-role-input]");
        const trigger = dropdown.querySelector("[data-role-trigger]");
        const label = dropdown.querySelector("[data-role-label]");
        const options = dropdown.querySelectorAll("[data-role-option]");
        const placeholder = dropdown.getAttribute("data-placeholder") || "Select Role";
        const form = dropdown.closest("form");

        if (!input || !trigger || !label || options.length === 0) return;

        function closeDropdown() {
            dropdown.classList.remove("is-open");
            trigger.setAttribute("aria-expanded", "false");
        }

        function closeOtherDropdowns() {
            document.querySelectorAll("[data-role-dropdown].is-open").forEach(function (openDropdown) {
                if (openDropdown !== dropdown) {
                    const openTrigger = openDropdown.querySelector("[data-role-trigger]");
                    openDropdown.classList.remove("is-open");
                    if (openTrigger) {
                        openTrigger.setAttribute("aria-expanded", "false");
                    }
                }
            });
        }

        function syncSelectedState() {
            const selectedOption = Array.from(options).find(function (option) {
                return option.dataset.value === input.value;
            });

            label.textContent = selectedOption ? selectedOption.textContent.trim() : placeholder;
            dropdown.classList.toggle("has-value", Boolean(input.value));
            dropdown.classList.remove("is-invalid");

            options.forEach(function (option) {
                const isSelected = option.dataset.value === input.value;
                option.classList.toggle("is-selected", isSelected);
                option.setAttribute("aria-selected", isSelected ? "true" : "false");
            });
        }

        trigger.addEventListener("click", function () {
            const isOpen = dropdown.classList.contains("is-open");
            closeOtherDropdowns();
            dropdown.classList.toggle("is-open", !isOpen);
            trigger.setAttribute("aria-expanded", !isOpen ? "true" : "false");
        });

        trigger.addEventListener("keydown", function (event) {
            if (event.key === "Enter" || event.key === " " || event.key === "ArrowDown") {
                event.preventDefault();
                closeOtherDropdowns();
                dropdown.classList.add("is-open");
                trigger.setAttribute("aria-expanded", "true");
            }

            if (event.key === "Escape") {
                closeDropdown();
            }
        });

        options.forEach(function (option) {
            option.addEventListener("click", function () {
                const nextValue = option.dataset.value || "";

                if (input.value !== nextValue) {
                    input.value = nextValue;
                    input.dispatchEvent(new Event("change", { bubbles: true }));
                } else {
                    syncSelectedState();
                }

                closeDropdown();
                trigger.focus();
            });
        });

        document.addEventListener("click", function (event) {
            if (!dropdown.contains(event.target)) {
                closeDropdown();
            }
        });

        document.addEventListener("keydown", function (event) {
            if (event.key === "Escape") {
                closeDropdown();
            }
        });

        if (form) {
            form.addEventListener("submit", function (event) {
                if (!input.value) {
                    event.preventDefault();
                    dropdown.classList.add("is-invalid");
                    trigger.focus();
                }
            });
        }

        input.addEventListener("change", syncSelectedState);
        syncSelectedState();

    });

}

if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", initRoleDropdowns);
} else {
    initRoleDropdowns();
}


// -----------------------------
// Simple Search Filter
// -----------------------------

function searchItems() {

    const input = document.getElementById("searchInput");

    if (!input) return;

    const filter = input.value.toLowerCase();
    const items = document.querySelectorAll(".item-card");

    items.forEach(function (item) {

        const text = item.textContent.toLowerCase();

        if (text.includes(filter)) {
            item.style.display = "block";
        } else {
            item.style.display = "none";
        }

    });

}
