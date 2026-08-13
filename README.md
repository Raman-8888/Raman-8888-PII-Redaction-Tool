# Anonymize Documents with Presidio & Faker

A production-grade PII detection, redaction, and synthetic anonymization tool designed for PDF, Word (`.docx`), and PowerPoint (`.pptx`) documents using **Microsoft Presidio**, **spaCy NER**, and **Faker**.

---

## 🚀 Technical Approach

This project combines NLP statistical named-entity recognition (NER), regex pattern matching, and context-based recognizers to achieve high precision and recall on complex legal and financial documents (*Red Herring Prospectus*).

### Key Components:
1. **Detection Engine**: Microsoft Presidio Analyzer + spaCy `en_core_web_lg` NER model.
2. **Custom Recognizers**: Hand-crafted pattern recognizers for honorific names, context words (`Contact Person`, `Director`, `Promoter`), and regional financial IDs (PAN, DIN, CIN, Aadhaar).
3. **Multi-Pass Propagation**: Discovers full entity names in Pass 1 and dynamically propagates individual name tokens across the document in Pass 2 to eliminate missed standalone names.
4. **Synthetic Anonymizer**: Uses `Faker` to replace sensitive PII with realistic, consistent synthetic alternatives (e.g. `Rashi Patil` -> `John Doe`, `rashi@gmail.com` -> `john.doe@example.com`, `+91 9876543210` -> `+91 1234567890`).

---

## 🎯 Target Entity Coverage

- **Full Names** (`PERSON`)
- **Email Addresses** (`EMAIL_ADDRESS`)
- **Phone Numbers** (`PHONE_NUMBER`)
- **Company Names** (`ORGANIZATION`)
- **Physical/Mailing Addresses** (`LOCATION`)
- **Social Security Numbers** (`US_SSN`)
- **Credit Card Numbers** (`CREDIT_CARD`)
- **Dates of Birth** (`DATE_TIME`)
- **IP Addresses** (`IP_ADDRESS`)
- **Financial & Government IDs** (`IN_PAN`, `DIN`, `CIN`, `Aadhaar`, `Passport`)

---

## 💻 Usage & CLI Commands

### 1. Installation
```bash
pip install presidio-analyzer presidio-anonymizer spacy python-docx python-pptx pymupdf faker
python -m spacy download en_core_web_sm
```

### 2. Run Synthetic Anonymization (Fake Replacements)
```bash
python scripts/anonymize_document.py "input/Red Herring Prospectus_redacted.docx" "output/Red Herring Prospectus_anonymized.docx" --mode anonymize --report
```

### 3. Run Static Redaction (`[REDACTED]` Tokens)
```bash
python scripts/anonymize_document.py "input/Red Herring Prospectus_redacted.docx" "output/Red Herring Prospectus_redacted.docx" --mode redact --report
```

### 4. Custom Deny List & Score Threshold Tuning
```bash
python scripts/anonymize_document.py input/doc.docx output/doc.docx --deny-list "Custom Name,Company XYZ" --score-threshold 0.20
```

### 5. Directory Batch Processing
```bash
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

## 🧩 How to Extend to a New PII Type

To add a new entity type (e.g. `DRIVER_LICENSE`):
1. In `scripts/anonymize_document.py`, add `DRIVER_LICENSE` to `TARGET_ENTITIES` and `ENTITY_ALIASES`.
2. Add a `PatternRecognizer` with custom regex pattern inside `build_analyzer()`.
3. Add a synthetic generator case inside `SyntheticAnonymizer.get_replacement()`:
   ```python
   elif entity == "DRIVER_LICENSE":
       val = f"DL-{fake.random_number(digits=8)}"
   ```

---

## 🛡️ License & Credits
Licensed under MIT. Powered by Microsoft Presidio, spaCy, and Faker.