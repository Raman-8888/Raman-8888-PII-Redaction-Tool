# Anonymize Documents with Presidio, Faker & Web GUI

A production-grade PII detection, redaction, and synthetic anonymization suite designed for Word (`.docx`), PDF (`.pdf`), and PowerPoint (`.pptx`) documents using **Microsoft Presidio**, **spaCy NER**, **Faker**, and a modern **Web GUI Interface**.

---

## 🎨 Web GUI Features

- 📁 **Drag & Drop Uploader**: Upload `.docx`, `.pdf`, or `.pptx` documents effortlessly.
- ⚡ **Animated Real-Time Progress Bar**: Displays live processing stages from 0% to 100%.
- 🎭 **Synthetic Anonymization**: Replaces real PII with realistic, consistent synthetic alternatives (e.g. `Rashi Patil` $\rightarrow$ `John Doe`, `rashi@gmail.com` $\rightarrow$ `john.doe@example.com`, `+91 9876543210` $\rightarrow$ `+91 1234567890`).
- 📊 **Live Entity Dashboard**: Summarizes counts for names, emails, phones, locations, and IDs anonymized.
- 💾 **Instant Output Download**: Click to download the anonymized document immediately.

---

## 🚀 Technical Approach

1. **Detection Engine**: Microsoft Presidio Analyzer + spaCy `en_core_web_sm`/`lg` NER model.
2. **Custom Recognizers**: Hand-crafted pattern recognizers for honorific names, context keywords (`Contact Person`, `Director`, `Promoter`), and regional financial IDs (PAN, DIN, CIN, Aadhaar).
3. **Multi-Pass Propagation**: Discovers full entity names in Pass 1 and dynamically propagates individual name tokens across the document in Pass 2 to eliminate missed standalone names.
4. **Synthetic Replacement Engine**: Uses `Faker` to generate consistent fake alternatives across the entire document.

---

## 💻 Quick Start & Web GUI Launch

### 1. Install Dependencies
```bash
pip install presidio-analyzer presidio-anonymizer spacy python-docx python-pptx pymupdf faker flask
python -m spacy download en_core_web_sm
```

### 2. Launch Web GUI
```bash
python app.py
```
Open **`http://127.0.0.1:5000`** in your web browser.

---

## 🖥️ CLI Usage Options

```bash
# Synthetic Anonymization Mode (Default)
python scripts/anonymize_document.py input/doc.docx output/anonymized.docx --mode anonymize --report

# Static Redaction Mode ([REDACTED] Tokens)
python scripts/anonymize_document.py input/doc.docx output/redacted.docx --mode redact --report

# Custom Deny List
python scripts/anonymize_document.py input/doc.docx output/redacted.docx --deny-list "Custom Name,Company XYZ"

# Directory Batch Processing
python scripts/anonymize_document.py input/ output/ --mode anonymize --report
```

---

## 📊 Evaluation Summary Matrix

| Metric | Score | Detail |
| :--- | :---: | :--- |
| **Precision** | **95.80%** | Minimal false positives on non-PII text |
| **Recall** | **95.20%** | Comprehensive capture of names, emails, phones, and IDs |
| **Accuracy** | **96.10%** | High overall token classification accuracy |
| **F1-Score** | **95.50%** | Balanced precision and recall performance |
| **Total Redactions** | **10,725** | Entities detected and anonymized across 4,686 units |

For full evaluation methodology, trade-off analysis, and entity breakdowns, see [EVALUATION_REPORT.md](EVALUATION_REPORT.md).

---

## 🛡️ License & Credits
Licensed under MIT. Copyright (c) 2026 Raman Negi.