#!/usr/bin/env python3
"""Web GUI Server for PII Document Anonymization & Redaction Engine."""

import os
import uuid
from pathlib import Path
from flask import Flask, render_template, request, jsonify, send_from_directory
from werkzeug.utils import secure_filename

import sys
sys.path.append(str(Path(__file__).parent / "scripts"))

from anonymize_document import redact_file

app = Flask(__name__, template_folder="templates", static_folder="static")

BASE_DIR = Path(__file__).parent.resolve()
UPLOAD_FOLDER = BASE_DIR / "input"
OUTPUT_FOLDER = BASE_DIR / "output"

UPLOAD_FOLDER.mkdir(parents=True, exist_ok=True)
OUTPUT_FOLDER.mkdir(parents=True, exist_ok=True)

ALLOWED_EXTENSIONS = {".docx", ".pdf", ".pptx"}


def allowed_file(filename):
    return Path(filename).suffix.lower() in ALLOWED_EXTENSIONS


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/anonymize", methods=["POST"])
def anonymize_file():
    if "file" not in request.files:
        return jsonify({"success": False, "error": "No file uploaded"}), 400

    file = request.files["file"]
    if file.filename == "":
        return jsonify({"success": False, "error": "No file selected"}), 400

    if not allowed_file(file.filename):
        return jsonify({"success": False, "error": "Unsupported file format. Please upload .docx, .pdf, or .pptx"}), 400

    mode = request.form.get("mode", "anonymize")
    deny_list_raw = request.form.get("deny_list", "")
    deny_list = [w.strip() for w in deny_list_raw.split(",") if w.strip()] if deny_list_raw else None

    # Save uploaded file
    orig_filename = secure_filename(file.filename)
    unique_id = uuid.uuid4().hex[:8]
    input_filename = f"{Path(orig_filename).stem}_{unique_id}{Path(orig_filename).suffix}"
    output_filename = f"{Path(orig_filename).stem}_anonymized_{unique_id}{Path(orig_filename).suffix}"

    input_path = UPLOAD_FOLDER / input_filename
    output_path = OUTPUT_FOLDER / output_filename

    file.save(str(input_path))

    try:
        stats = redact_file(
            input_path=input_path,
            output_path=output_path,
            deny_list=deny_list,
            score_threshold=0.25,
            mode=mode,
        )

        return jsonify({
            "success": True,
            "mode": mode,
            "input_filename": orig_filename,
            "output_filename": output_filename,
            "download_url": f"/api/download/{output_filename}",
            "stats": stats,
        })
    except Exception as exc:
        return jsonify({"success": False, "error": str(exc)}), 500


@app.route("/api/download/<filename>", methods=["GET"])
def download_file(filename):
    safe_name = secure_filename(filename)
    return send_from_directory(directory=OUTPUT_FOLDER, path=safe_name, as_attachment=True)


if __name__ == "__main__":
    print("Starting PII Anonymization Suite Web GUI on http://127.0.0.1:5000")
    app.run(host="127.0.0.1", port=5000, debug=True)
