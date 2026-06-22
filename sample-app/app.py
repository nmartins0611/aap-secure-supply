"""Minimal Flask application for supply chain demo."""

from flask import Flask, jsonify

app = Flask(__name__)


@app.route("/healthz")
def health():
    return jsonify({"status": "ok"})


@app.route("/")
def index():
    return jsonify({
        "app": "trusted-pipeline-demo",
        "message": "Built with a verified, monitored, and signed supply chain",
    })


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080)
