from app import create_app
import os

app = create_app()

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))   # Render → auto, Local → 5000
    debug = os.environ.get("DEBUG", "True") == "True"

    app.run(host="0.0.0.0", port=port, debug=debug)