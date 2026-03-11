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
        .then(function(stream) {
            video.srcObject = stream;
        })
        .catch(function(error) {
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


// -----------------------------
// Simple Search Filter
// -----------------------------

function searchItems() {

    const input = document.getElementById("searchInput");

    if (!input) return;

    const filter = input.value.toLowerCase();
    const items = document.querySelectorAll(".item-card");

    items.forEach(function(item){

        const text = item.textContent.toLowerCase();

        if (text.includes(filter)) {
            item.style.display = "block";
        } else {
            item.style.display = "none";
        }

    });

}