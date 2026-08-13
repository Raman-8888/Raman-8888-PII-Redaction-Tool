document.addEventListener('DOMContentLoaded', () => {
  const dropzone = document.getElementById('dropzone');
  const fileInput = document.getElementById('fileInput');
  const fileDetails = document.getElementById('fileDetails');
  const fileNameDisplay = document.getElementById('fileName');
  const removeFileBtn = document.getElementById('removeFileBtn');
  const anonymizeBtn = document.getElementById('anonymizeBtn');
  const modeSelect = document.getElementById('modeSelect');
  const denyListInput = document.getElementById('denyList');

  const progressSection = document.getElementById('progressSection');
  const progressStatus = document.getElementById('progressStatus');
  const progressPercent = document.getElementById('progressPercent');
  const progressBarFill = document.getElementById('progressBarFill');

  const resultsSection = document.getElementById('resultsSection');
  const metricTotal = document.getElementById('metricTotal');
  const metricPerson = document.getElementById('metricPerson');
  const metricEmail = document.getElementById('metricEmail');
  const metricPhone = document.getElementById('metricPhone');
  const downloadBtn = document.getElementById('downloadBtn');

  let selectedFile = null;

  // Dropzone click triggers input
  dropzone.addEventListener('click', (e) => {
    if (e.target !== removeFileBtn) {
      fileInput.click();
    }
  });

  // Drag & drop handlers
  ['dragenter', 'dragover'].forEach(eventName => {
    dropzone.addEventListener(eventName, (e) => {
      e.preventDefault();
      dropzone.classList.add('dragover');
    });
  });

  ['dragleave', 'drop'].forEach(eventName => {
    dropzone.addEventListener(eventName, (e) => {
      e.preventDefault();
      dropzone.classList.remove('dragover');
    });
  });

  dropzone.addEventListener('drop', (e) => {
    const files = e.dataTransfer.files;
    if (files.length > 0) {
      handleFileSelection(files[0]);
    }
  });

  fileInput.addEventListener('change', (e) => {
    if (fileInput.files.length > 0) {
      handleFileSelection(fileInput.files[0]);
    }
  });

  function handleFileSelection(file) {
    const ext = file.name.split('.').pop().toLowerCase();
    if (!['docx', 'pdf', 'pptx'].includes(ext)) {
      alert('Please select a valid Word (.docx), PDF (.pdf), or PowerPoint (.pptx) file.');
      return;
    }
    selectedFile = file;
    fileNameDisplay.textContent = file.name;
    fileDetails.classList.remove('hidden');
    anonymizeBtn.disabled = false;
    resultsSection.classList.add('hidden');
    progressSection.classList.add('hidden');
  }

  removeFileBtn.addEventListener('click', (e) => {
    e.stopPropagation();
    selectedFile = null;
    fileInput.value = '';
    fileDetails.classList.add('hidden');
    anonymizeBtn.disabled = true;
    resultsSection.classList.add('hidden');
    progressSection.classList.add('hidden');
  });

  // Anonymize button click
  anonymizeBtn.addEventListener('click', async () => {
    if (!selectedFile) return;

    anonymizeBtn.disabled = true;
    resultsSection.classList.add('hidden');
    progressSection.classList.remove('hidden');

    // Simulate progress stages
    updateProgress(15, 'Uploading document...');

    const formData = new FormData();
    formData.append('file', selectedFile);
    formData.append('mode', modeSelect.value);
    formData.append('deny_list', denyListInput.value);

    setTimeout(() => updateProgress(40, 'Running Presidio NLP entity detection...'), 800);
    setTimeout(() => updateProgress(70, 'Generating synthetic replacements (Names, Phones, Emails)...'), 1800);
    setTimeout(() => updateProgress(88, 'Scrubbing document metadata & saving file...'), 2800);

    try {
      const response = await fetch('/api/anonymize', {
        method: 'POST',
        body: formData
      });

      const data = await response.json();

      if (response.ok && data.success) {
        updateProgress(100, 'Processing Complete!');
        setTimeout(() => {
          progressSection.classList.add('hidden');
          showResults(data);
          anonymizeBtn.disabled = false;
        }, 500);
      } else {
        alert('Anonymization failed: ' + (data.error || 'Unknown error'));
        progressSection.classList.add('hidden');
        anonymizeBtn.disabled = false;
      }
    } catch (err) {
      alert('Network error during file processing.');
      progressSection.classList.add('hidden');
      anonymizeBtn.disabled = false;
    }
  });

  function updateProgress(percent, statusText) {
    progressBarFill.style.width = percent + '%';
    progressPercent.textContent = percent + '%';
    progressStatus.textContent = statusText;
  }

  function showResults(data) {
    const stats = data.stats || {};
    const entities = stats.entities || {};

    metricTotal.textContent = stats.redactions || 0;
    metricPerson.textContent = entities.PERSON || 0;
    metricEmail.textContent = entities.EMAIL_ADDRESS || 0;
    metricPhone.textContent = entities.PHONE_NUMBER || 0;

    downloadBtn.href = data.download_url;
    downloadBtn.setAttribute('download', data.output_filename);

    resultsSection.classList.remove('hidden');
  }
});
