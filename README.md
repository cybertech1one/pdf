# pdf
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>Advanced PDF Security Scanner Pro</title>
  <meta name="viewport" content="width=device-width, initial-scale=1">
  
  <!-- Tailwind CSS -->
  <script src="https://cdn.tailwindcss.com"></script>
  
  <!-- PDF.js -->
  <script src="https://cdn.jsdelivr.net/npm/pdfjs-dist@3.11.174/build/pdf.min.js"></script>
  <script>
    window.onload = function() {
      pdfjsLib.GlobalWorkerOptions.workerSrc =
        'https://cdn.jsdelivr.net/npm/pdfjs-dist@3.11.174/build/pdf.worker.min.js';
    }
  </script>
  
  <!-- Other Dependencies -->
  <script src="https://cdnjs.cloudflare.com/ajax/libs/dompurify/3.0.9/purify.min.js"></script>
  <script src="https://cdnjs.cloudflare.com/ajax/libs/crypto-js/4.2.0/crypto-js.min.js"></script>
  <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
  
  <!-- Styling & Layout -->
  <style>
    .dropzone {
      border: 2px dashed #ccc;
      transition: all 0.3s ease;
    }
    .dropzone.dragover {
      border-color: #4299e1;
      background: rgba(66, 153, 225, 0.1);
    }
    .loading {
      border: 3px solid #f3f3f3;
      border-top: 3px solid #3498db;
      border-radius: 50%;
      width: 20px;
      height: 20px;
      animation: spin 1s linear infinite;
      display: inline-block;
      margin-left: 10px;
      vertical-align: middle;
    }
    @keyframes spin {
      0% { transform: rotate(0deg); }
      100% { transform: rotate(360deg); }
    }
    .tree-view {
      font-family: monospace;
    }
    .tree-view ul {
      list-style: none;
      padding-left: 20px;
    }
    .tree-view li:before {
      content: "└─ ";
      color: #666;
    }
    .threat-score {
      font-size: 24px;
      font-weight: bold;
      text-align: center;
      padding: 20px;
      border-radius: 50%;
      width: 80px;
      height: 80px;
      display: flex;
      align-items: center;
      justify-content: center;
      margin: 0 auto;
    }
    nav.tab-buttons button {
      flex: 1;
      text-align: center;
      padding: 0.75rem;
      border: none;
      cursor: pointer;
      font-weight: 500;
      border-bottom: 2px solid transparent;
      transition: background 0.2s ease;
    }
    nav.tab-buttons button.active {
      border-bottom: 2px solid #4299e1;
      color: #4299e1;
    }
    nav.tab-buttons button:hover {
      background: #f9fafb;
    }
  </style>
</head>

<body class="bg-gray-100 min-h-screen">
  <div class="container mx-auto px-4 py-8">
    <div class="bg-white rounded-lg shadow-lg p-6">
      <!-- Title -->
      <h1 class="text-3xl font-bold mb-6 text-center text-gray-800">
        Advanced PDF Security Scanner Pro
        <span class="text-sm font-normal text-gray-500 block mt-2">
          Deep Analysis &amp; Threat Detection
        </span>
      </h1>
      
      <!-- Drop Zone -->
      <div class="dropzone rounded-lg px-8 py-12 text-center mb-10" id="dropZone">
        <div class="mb-4">
          <svg class="mx-auto h-12 w-12 text-gray-400" stroke="currentColor" fill="none" viewBox="0 0 48 48">
            <path d="M28 8H12a4 4 0 00-4 4v20m32-12v8m0 0v8a4 4 0 01-4 4H12a4 4 0 01-4-4v-4m32-4l-3.172-3.172a4 4 0 00-5.656 0L28 28M8 32l9.172-9.172a4 4 0 015.656 0L28 28m0 0l4 4m4-24h8m-4-4v8m-12 4h.02"
                  stroke-width="2" stroke-linecap="round" stroke-linejoin="round" />
          </svg>
          <div class="mt-4">
            <input type="file" id="pdfInput" accept="application/pdf" class="hidden">
            <label for="pdfInput" class="cursor-pointer bg-blue-500 text-white px-6 py-2 rounded-md hover:bg-blue-600 transition inline-block">
              Select PDF File
            </label>
            <p class="mt-2 text-sm text-gray-500">
              or drag &amp; drop PDF here
            </p>
          </div>
        </div>
      </div>
      
      <!-- Buttons -->
      <div class="flex justify-center flex-wrap gap-4 mb-8">
        <button id="scanButton" class="bg-blue-500 text-white px-6 py-3 rounded-lg hover:bg-blue-600 transition flex items-center">
          <svg class="w-5 h-5 mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2"
                  d="M9 5H7a2 2 0 00-2 2v12a2 2 0 002 2h10a2 2 0 002-2V7a2 2 0 00-2-2h-2
                     M9 5a2 2 0 002 2h2a2 2 0 002-2
                     M9 5a2 2 0 012-2h2a2 2 0 012 2"/>
          </svg>
          Start Deep Scan
          <span id="spinner" class="loading hidden"></span>
        </button>
        <button id="downloadReport" class="bg-green-500 text-white px-6 py-3 rounded-lg hover:bg-green-600 transition hidden flex items-center">
          <svg class="w-5 h-5 mr-2 inline" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2"
                  d="M12 10v6m0 0l-3-3m3 3l3-3
                     m2 8H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z"/>
          </svg>
          Download Report
        </button>
      </div>
      
      <!-- Progress Bar -->
      <div id="progressContainer" class="hidden mb-8">
        <div class="flex justify-between mb-2">
          <span id="progressText" class="text-sm font-medium text-gray-700">Initializing...</span>
          <span id="progressPercent" class="text-sm font-medium text-gray-700">0%</span>
        </div>
        <div class="w-full bg-gray-200 rounded-full h-2.5">
          <div id="progressBar" class="bg-blue-600 h-2.5 rounded-full transition-all duration-300" style="width: 0%"></div>
        </div>
        <div id="progressDetails" class="mt-2 text-sm text-gray-500"></div>
      </div>
      
      <!-- Results Dashboard -->
      <div id="resultsDashboard" class="hidden">
        <div class="grid grid-cols-1 md:grid-cols-3 gap-6 mb-10">
          <div class="bg-white rounded-lg shadow p-6 text-center">
            <h3 class="text-lg font-semibold mb-4 text-gray-700">Overall Threat Score</h3>
            <div id="threatScore" class="threat-score"></div>
          </div>
          <div class="bg-white rounded-lg shadow p-6">
            <h3 class="text-lg font-semibold mb-4 text-gray-700">Risk Categories</h3>
            <canvas id="riskChart"></canvas>
          </div>
          <div class="bg-white rounded-lg shadow p-6">
            <h3 class="text-lg font-semibold mb-4 text-gray-700">Quick Stats</h3>
            <div id="quickStats" class="text-sm text-gray-700"></div>
          </div>
        </div>
        
        <div class="border-b border-gray-200 mb-6">
          <nav class="tab-buttons flex" aria-label="Tabs">
            <button class="tab-button active" data-tab="security">Security Analysis</button>
            <button class="tab-button" data-tab="structure">PDF Structure</button>
            <button class="tab-button" data-tab="objects">Objects</button>
            <button class="tab-button" data-tab="metadata">Metadata</button>
            <button class="tab-button" data-tab="preview">Content Preview</button>
          </nav>
        </div>
        
        <div class="space-y-8">
          <div id="securityTab" class="tab-content active">
            <div id="securityResults" class="space-y-4"></div>
          </div>
          
          <div id="structureTab" class="tab-content hidden">
            <div id="pdfStructure" class="tree-view p-4 bg-gray-50 rounded-md"></div>
          </div>
          
          <div id="objectsTab" class="tab-content hidden">
            <h4 class="text-lg font-semibold mb-4 text-gray-700">Deep Annotation Analysis</h4>
            <div id="annotationDetails" class="text-sm space-y-2 bg-gray-50 p-4 rounded-md"></div>
          </div>
          
          <div id="metadataTab" class="tab-content hidden">
            <div id="metadata" class="font-mono text-sm p-4 bg-gray-50 rounded-md"></div>
          </div>
          
          <div id="previewTab" class="tab-content hidden">
            <textarea id="pdfText" readonly class="w-full h-96 p-4 font-mono text-sm border rounded"></textarea>
          </div>
        </div>
      </div>
    </div>
  </div>
  
  <!-- SCRIPT: Security Patterns & PDF Scanning Logic -->
  <script>
    // --------------------------------------------------------------------------------
    // 1) SECURITY PATTERNS
    // --------------------------------------------------------------------------------
    const securityPatterns = {
      javascript: {
        patterns: [
          { regex: /\/JavaScript|\/JS\s*\(/gi, severity: "critical" },
          { regex: /eval\(|new\s+Function|setTimeout|setInterval/gi, severity: "critical" },
          { regex: /Function\(['"`]return.*?['"`]\)/gi, severity: "critical" },
          { regex: /document\.|window\.|global\.|process\.|require\(|import\s+|module\./gi, severity: "high" },
          { regex: /this\.exportDataObject\s*\(|this\.mailDoc\s*\(|this\.submitForm\s*\(|this\.print\s*\(/gi, severity: "high" },
          { regex: /app\.launchURL\s*\(|app\.execMenuItem\s*\(|app\.alert\s*\(/gi, severity: "high" },
          { regex: /\.getAnnots|\.getField|\.getIcon|\.getLinks/gi, severity: "high" },
          { regex: /\\x[0-9A-Fa-f]{2}|\\u[0-9A-Fa-f]{4}|%u[0-9A-Fa-f]{4}/gi, severity: "medium" },
          { regex: /unescape\s*\(|String\.fromCharCode\s*\(/gi, severity: "medium" }
        ],
        description: "JavaScript code detection"
      },
      networkActivity: {
        patterns: [
          { regex: /(https?|ftp|file|data|blob):\/\/[^\s<>"']+/gi, severity: "medium" },
          { regex: /\/URI\s*\(|\/URL\s*\(|\/Launch\s*\(|\/SubmitForm/gi, severity: "high" },
          { regex: /\/GoTo(?:E|R)?|\/Launch|\/Thread|\/Sound/gi, severity: "medium" }
        ],
        description: "Network activity detection"
      },
      pdfStructure: {
        patterns: [
          { regex: /\/OpenAction|\/AA|\/Launch|\/JavaScript|\/RichMedia/gi, severity: "critical" },
          { regex: /\/XFA|\/AcroForm|\/JBIG2Decode|\/CCITTFaxDecode/gi, severity: "high" },
          { regex: /\/ObjStm|\/XRef|\/EmbeddedFile|\/FileSpec/gi, severity: "medium" }
        ],
        description: "PDF structure analysis"
      },
      maliciousPatterns: {
        patterns: [
          { regex: /\b(?:cmd|shell|powershell|wscript)\b.*?\b(?:\/c|exec|run)/gi, severity: "critical" },
          { regex: /\b(?:password|passwd|pwd|credential|token|api[_-]?key|secret)/gi, severity: "high" },
          { regex: /(?:\\x[0-9a-fA-F]{2}|\\u[0-9a-fA-F]{4}|%u[0-9a-fA-F]{4}){3,}/gi, severity: "high" },
          { regex: /\bb64encode|\bb64decode|\bexec\(|base64decode|base64encode/gi, severity: "high" },
          { regex: /(onerror\s*=|onload\s*=|alert\s*\(|prompt\s*\(|confirm\s*\()/gi, severity: "medium" }
        ],
        description: "Malicious pattern detection"
      },
      xssAttacks: {
        patterns: [
          { regex: /<script[\s\S]*?>[\s\S]*?<\/script>/gi, severity: "critical" },
          { regex: /<img[^>]+src\s*=\s*['"]javascript:/gi, severity: "high" },
          { regex: /<iframe[\s\S]*?>[\s\S]*?<\/iframe>/gi, severity: "high" },
          { regex: /on\w+\s*=\s*(["']?).*?\1/gi, severity: "medium" },
          { regex: /document\.cookie|window\.location|document\.location/gi, severity: "medium" },
          { regex: /<(style|link)[^>]+(javascript:)/gi, severity: "high" },
          { regex: /expression\s*\(/gi, severity: "medium" }
        ],
        description: "Common XSS injection patterns"
      },
      ssrfAndBeacons: {
        patterns: [
          { regex: /(?<![\w])(https?:\/\/(?:127\.0\.0\.1|localhost|169\.254\.\d+\.\d+))/gi, severity: "critical" },
          { regex: /(?<![\w])(https?:\/\/(10\.\d+\.\d+\.\d+|192\.168\.\d+\.\d+|172\.(1[6-9]|2[0-9]|3[0-1])\.\d+\.\d+))/gi, severity: "critical" },
          { regex: /https?:\/\/(exfil|callback|beacon)\.[^\s<>"']+/gi, severity: "high" },
          { regex: /https?:\/\/[^\s]*burpcollaborator\.net[^\s]*/gi, severity: "high" },
          { regex: /\/etc\/passwd|\/etc\/shadow|metadata\.google\.internal|169\.254\.169\.254/gi, severity: "high" }
        ],
        description: "SSRF and potential beacon endpoints"
      },
      obfuscationAndHidden: {
        patterns: [
          { regex: /[A-Za-z0-9+\/]{40,}={0,2}/g, severity: "medium" },
          { regex: /[\u200B-\u200F\uFEFF\u2028\u2029]/g, severity: "medium" },
          { regex: /(script){3,}/gi, severity: "high" }
        ],
        description: "Potential hidden or obfuscated content"
      },
      // NEW: Enhanced Reverse Shell detection with multiple shell payloads
      reverseShell: {
        patterns: [
          // Bash reverse shell
          { regex: /bash\s+-i\s*>\&\s*\/dev\/tcp\/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\/\d+\s+0>&1/gi, severity: "critical" },
          // Netcat reverse shell (nc)
          { regex: /nc\s+-e\s+\/bin\/sh\s+\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\s+\d+/gi, severity: "critical" },
          // Ncat reverse shell (ncat)
          { regex: /ncat\s+-e\s+\/bin\/sh\s+\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\s+\d+/gi, severity: "critical" },
          // Perl reverse shell
          { regex: /perl\s+-e\s+'.*socket\(/gi, severity: "critical" },
          // Python reverse shell
          { regex: /python\s+-c\s+'.*socket\.socket\(/gi, severity: "critical" },
          // PHP reverse shell
          { regex: /php\s+-r\s+'.*fsockopen\(/gi, severity: "critical" },
          // PowerShell reverse shell
          { regex: /powershell\s+-nop\s+-c\s+".*New-Object\s+Net\.Sockets\.TCPClient/gi, severity: "critical" }
        ],
        description: "Reverse shell command detection"
      }
    };
    
    // --------------------------------------------------------------------------------
    // 2) PDF ANALYZER CLASS
    // --------------------------------------------------------------------------------
    class PDFAnalyzer {
      constructor() {
        this.results = {
          metadata: {},
          security: {},
          structure: {},
          text: "",
          deepAnnotations: [],
          rawScanFindings: [],
          stats: {
            threatScore: 0,
            totalIssues: 0
          }
        };
      }
    
      async analyzePDF(arrayBuffer) {
        try {
          this.updateProgress(0, "Initializing analysis...");
    
          // 1) Raw scan of PDF data for embedded files, XFA, polyglot signatures, etc.
          const rawScanReport = this.scanRawPDFData(arrayBuffer);
          this.results.rawScanFindings = rawScanReport.findings;
    
          // 2) Calculate file hash
          this.results.fileHash = CryptoJS.SHA256(
            CryptoJS.lib.WordArray.create(arrayBuffer)
          ).toString();
    
          // 3) Load PDF using PDF.js
          const pdf = await pdfjsLib.getDocument({ data: arrayBuffer }).promise;
    
          this.updateProgress(20, "Extracting metadata...");
          await this.extractMetadata(pdf);
    
          this.updateProgress(40, "Analyzing PDF structure...");
          await this.analyzePDFStructure(pdf);
    
          this.updateProgress(60, "Extracting text content...");
          await this.extractContent(pdf);
    
          this.updateProgress(70, "Parsing annotation actions...");
          await this.deepScanAnnotations(pdf);
    
          this.updateProgress(80, "Performing security analysis...");
          await this.performSecurityAnalysis();
    
          this.updateProgress(90, "Calculating threat score...");
          this.calculateThreatScore();
    
          this.updateProgress(100, "Analysis complete");
    
          return this.results;
        } catch (error) {
          throw new Error(`PDF Analysis failed: ${error.message}`);
        }
      }
    
      // Raw PDF Data Scan
      scanRawPDFData(arrayBuffer) {
        const findings = [];
        const rawBytes = new Uint8Array(arrayBuffer);
        const textData = new TextDecoder().decode(rawBytes);
    
        // Embedded File references
        const embedMatch = textData.match(/\/EmbeddedFile|\/Filespec/gi);
        if (embedMatch) {
          findings.push({
            type: "Potential EmbeddedFile",
            message: `Detected ${embedMatch.length} reference(s) to /EmbeddedFile or /Filespec`,
            severity: "high"
          });
        }
    
        // XFA references
        const xfaMatch = textData.match(/\/XFA/gi);
        if (xfaMatch) {
          findings.push({
            type: "XFA Detected",
            message: `Detected ${xfaMatch.length} reference(s) to /XFA (XML Forms)`,
            severity: "medium"
          });
        }
    
        // Polyglot detection: ZIP/Office doc, OLE, PE
        const signatureMap = [
          { name: "ZIP/Office doc", regex: /\x50\x4B\x03\x04/g, severity: "medium" },
          { name: "OLE2/Doc", regex: /\xD0\xCF\x11\xE0/g, severity: "medium" },
          { name: "PE EXE", regex: /\x4D\x5A/g, severity: "high" }
        ];
    
        for (const sig of signatureMap) {
          if (sig.regex.test(rawBytes)) {
            findings.push({
              type: "Polyglot Signature",
              message: `Detected possible ${sig.name} signature in PDF data`,
              severity: sig.severity
            });
          }
        }
    
        return { findings };
      }
    
      // Metadata Extraction
      async extractMetadata(pdf) {
        try {
          const metadata = await pdf.getMetadata();
          this.results.metadata = {
            version: pdf.pdfInfo?.version || 'Unknown',
            pageCount: pdf.numPages,
            encrypted: pdf.pdfInfo?.encrypted || false,
            ...metadata.info
          };
        } catch (error) {
          console.warn('Metadata extraction error:', error);
          this.results.metadata = {
            version: 'Unknown',
            pageCount: pdf.numPages,
            encrypted: false,
            error: 'Failed to extract metadata'
          };
        }
      }
    
      // Structure Analysis
      async analyzePDFStructure(pdf) {
        this.results.structure = {
          pages: [],
          annotations: [],
          forms: []
        };
    
        try {
          for (let i = 1; i <= pdf.numPages; i++) {
            const page = await pdf.getPage(i);
            const annotations = await page.getAnnotations();
            this.results.structure.annotations.push(...annotations);
    
            const pageStructure = {
              pageNumber: i,
              annotations: annotations.length,
              hasJavaScript: annotations.some(a => a.subtype === 'JavaScript'),
              hasLinks: annotations.some(a => a.subtype === 'Link'),
              hasActions: annotations.some(a => a.actions && Object.keys(a.actions).length > 0)
            };
    
            this.results.structure.pages.push(pageStructure);
          }
        } catch (error) {
          console.warn('Structure analysis error:', error);
        }
      }
    
      // Text Extraction
      async extractContent(pdf) {
        let text = "";
        for (let i = 1; i <= pdf.numPages; i++) {
          try {
            const page = await pdf.getPage(i);
            const content = await page.getTextContent();
            text += content.items.map(item => item.str).join(" ") + "\n";
          } catch (error) {
            console.warn(`Error extracting text from page ${i}:`, error);
            text += `[Error extracting page ${i}]\n`;
          }
        }
        this.results.text = text;
      }
    
      // Deep Annotation Scanning
      async deepScanAnnotations(pdf) {
        try {
          for (let i = 1; i <= pdf.numPages; i++) {
            const page = await pdf.getPage(i);
            const annotations = await page.getAnnotations({ intent: 'display' });
    
            for (const ann of annotations) {
              let details = {
                page: i,
                subtype: ann.subtype || "Unknown",
                fieldName: ann.fieldName || "",
                url: ann.url || "",
                contents: ann.contents || "",
                actions: ""
              };
    
              if (ann.actions) {
                details.actions = JSON.stringify(ann.actions);
              }
    
              let combined = `
                page: ${details.page},
                subtype: ${details.subtype},
                fieldName: ${details.fieldName},
                url: ${details.url},
                contents: ${details.contents},
                actions: ${details.actions}
              `;
              this.results.deepAnnotations.push(combined);
            }
          }
        } catch (error) {
          console.warn('deepScanAnnotations error:', error);
        }
      }
    
      // Security Analysis
      async performSecurityAnalysis() {
        this.results.security = {};
    
        // 1) Scan the main rendered text
        for (const [category, data] of Object.entries(securityPatterns)) {
          this.results.security[category] = [];
          const matches = this.matchPatterns(this.results.text, data.patterns);
          if (matches.length) {
            this.results.security[category].push(...matches);
          }
        }
    
        // 2) Scan annotation-based text
        const annotationText = this.results.deepAnnotations.join("\n");
        for (const [category, data] of Object.entries(securityPatterns)) {
          const found = this.matchPatterns(annotationText, data.patterns);
          if (found.length) {
            if (!this.results.security[category]) {
              this.results.security[category] = [];
            }
            this.results.security[category].push(...found);
          }
        }
    
        // 3) Scan raw PDF scan findings
        const rawScanText = this.results.rawScanFindings.map(item => JSON.stringify(item)).join("\n");
        for (const [category, data] of Object.entries(securityPatterns)) {
          const found = this.matchPatterns(rawScanText, data.patterns);
          if (found.length) {
            if (!this.results.security[category]) {
              this.results.security[category] = [];
            }
            this.results.security[category].push(...found);
          }
        }
      }
    
      // Helper: Match patterns
      matchPatterns(text, patterns) {
        const findings = [];
        for (const { regex, severity } of patterns) {
          const matches = text.match(regex);
          if (matches) {
            findings.push({
              severity,
              matches: matches.length,
              examples: matches.slice(0, 3),
              pattern: regex.source
            });
          }
        }
        return findings;
      }
    
      // Threat Scoring
      calculateThreatScore() {
        const severityWeights = {
          critical: 100,
          high: 70,
          medium: 40,
          low: 10
        };
    
        let totalScore = 0;
        let totalIssues = 0;
    
        for (const category of Object.values(this.results.security)) {
          for (const finding of category) {
            const weight = severityWeights[finding.severity] || severityWeights.low;
            totalScore += weight * finding.matches;
            totalIssues += finding.matches;
          }
        }
    
        this.results.stats = {
          threatScore: totalIssues > 0 ? Math.min(100, Math.round(totalScore / totalIssues)) : 0,
          totalIssues: totalIssues
        };
      }
    
      // Progress Updates
      updateProgress(percent, message) {
        const event = new CustomEvent('analysisProgress', {
          detail: { percent, message }
        });
        window.dispatchEvent(event);
      }
    }
    
    // --------------------------------------------------------------------------------
    // 3) UI HANDLER CLASS
    // --------------------------------------------------------------------------------
    class UIHandler {
      constructor() {
        this.analyzer = new PDFAnalyzer();
        this.setupEventListeners();
      }
    
      setupEventListeners() {
        const dropZone = document.getElementById('dropZone');
        const fileInput = document.getElementById('pdfInput');
    
        dropZone.addEventListener('dragover', (e) => {
          e.preventDefault();
          dropZone.classList.add('dragover');
        });
        dropZone.addEventListener('dragleave', () => {
          dropZone.classList.remove('dragover');
        });
        dropZone.addEventListener('drop', (e) => {
          e.preventDefault();
          dropZone.classList.remove('dragover');
          const file = e.dataTransfer.files[0];
          if (file?.type === 'application/pdf') {
            fileInput.files = e.dataTransfer.files;
            this.handleFileSelection(file);
          } else {
            alert('Please drop a PDF file');
          }
        });
    
        fileInput.addEventListener('change', () => {
          const file = fileInput.files[0];
          if (file) this.handleFileSelection(file);
        });
    
        document.getElementById('scanButton').addEventListener('click', () => {
          const file = document.getElementById('pdfInput').files[0];
          if (file) {
            this.handleFileSelection(file);
          } else {
            alert('Please select a PDF file');
          }
        });
    
        window.addEventListener('analysisProgress', (e) => {
          this.updateProgress(e.detail.percent, e.detail.message);
        });
    
        document.querySelectorAll('.tab-button').forEach(button => {
          button.addEventListener('click', () => this.switchTab(button.dataset.tab));
        });
    
        document.getElementById('downloadReport').addEventListener('click', () => {
          this.generateReport(this.lastResults);
        });
      }
    
      async handleFileSelection(file) {
        const button = document.getElementById('scanButton');
        const spinner = document.getElementById('spinner');
        try {
          button.disabled = true;
          spinner.classList.remove('hidden');
          document.getElementById('progressContainer').classList.remove('hidden');
          document.getElementById('progressDetails').textContent = `File Selected: ${file.name}`;
          const arrayBuffer = await file.arrayBuffer();
          const results = await this.analyzer.analyzePDF(arrayBuffer);
          this.lastResults = results;
          this.displayResults(results, file.name);
        } catch (error) {
          console.error(error);
          alert(`Error analyzing PDF: ${error.message}`);
        } finally {
          button.disabled = false;
          spinner.classList.add('hidden');
          document.getElementById('progressContainer').classList.add('hidden');
        }
      }
    
      updateProgress(percent, message) {
        const progressBar = document.getElementById('progressBar');
        const progressText = document.getElementById('progressText');
        const progressPercent = document.getElementById('progressPercent');
        const progressDetails = document.getElementById('progressDetails');
        progressBar.style.width = `${percent}%`;
        progressPercent.textContent = `${Math.round(percent)}%`;
        progressText.textContent = "Scanning...";
        progressDetails.textContent = message;
      }
    
      displayResults(results, fileName) {
        document.getElementById('resultsDashboard').classList.remove('hidden');
        document.getElementById('downloadReport').classList.remove('hidden');
    
        const threatScore = document.getElementById('threatScore');
        const score = results.stats.threatScore;
        let scoreClass = '';
        if (score > 80) scoreClass = 'bg-red-100 text-red-700';
        else if (score > 60) scoreClass = 'bg-orange-100 text-orange-700';
        else if (score > 40) scoreClass = 'bg-yellow-100 text-yellow-700';
        else scoreClass = 'bg-green-100 text-green-700';
        threatScore.className = `threat-score ${scoreClass}`;
        threatScore.textContent = score;
    
        document.getElementById('quickStats').innerHTML = `
          <div class="grid grid-cols-2 gap-2">
            <div class="font-semibold">File Name:</div>
            <div>${fileName}</div>
            <div class="font-semibold">Total Issues:</div>
            <div>${results.stats.totalIssues}</div>
            <div class="font-semibold">Pages:</div>
            <div>${results.metadata.pageCount}</div>
            <div class="font-semibold">Version:</div>
            <div>${results.metadata.version}</div>
            <div class="font-semibold">File Hash:</div>
            <div class="text-xs break-all">${results.fileHash}</div>
          </div>
        `;
    
        let securityHTML = '';
        for (const [category, findings] of Object.entries(results.security)) {
          if (findings.length > 0) {
            const severityClasses = {
              critical: 'bg-red-50 border-red-500 text-red-700',
              high: 'bg-orange-50 border-orange-500 text-orange-700',
              medium: 'bg-yellow-50 border-yellow-500 text-yellow-700',
              low: 'bg-green-50 border-green-500 text-green-700'
            };
            securityHTML += `
              <div class="mb-6">
                <h3 class="text-lg font-semibold mb-3">${this.formatCategoryName(category)}</h3>
                ${findings.map(finding => `
                  <div class="mb-4 p-4 rounded-lg ${severityClasses[finding.severity] || 'border-gray-300'} border-l-4">
                    <div class="flex justify-between items-center">
                      <span class="font-semibold">
                        ${finding.severity.toUpperCase()}
                      </span>
                      <span class="text-sm px-2 py-1 rounded">
                        ${finding.matches} match(es)
                      </span>
                    </div>
                    <div class="mt-2 text-sm">
                      <div class="font-mono bg-white bg-opacity-50 p-2 rounded">
                        Pattern: ${this.escapeHtml(finding.pattern)}
                      </div>
                      ${finding.examples ? `
                        <div class="mt-2">
                          <div class="font-semibold">Examples:</div>
                          <ul class="list-disc list-inside">
                            ${finding.examples.map(ex => `
                              <li>${this.escapeHtml(ex)}</li>
                            `).join('')}
                          </ul>
                        </div>
                      ` : ''}
                    </div>
                  </div>
                `).join('')}
              </div>
            `;
          }
        }
        document.getElementById('securityResults').innerHTML =
          securityHTML || '<div class="text-green-600 text-center py-4">No security issues found</div>';
    
        this.displayStructureAnalysis(results.structure);
    
        const annotationContainer = document.getElementById('annotationDetails');
        if (results.deepAnnotations.length > 0) {
          annotationContainer.innerHTML = `
            <p class="mb-2">Raw annotation data (including actions):</p>
            <ul class="list-disc pl-5 space-y-2">
              ${results.deepAnnotations.map((ann, idx) => `
                <li>
                  <pre class="whitespace-pre-wrap bg-gray-50 p-2 rounded text-xs">
                    ${this.escapeHtml(ann)}
                  </pre>
                </li>
              `).join('')}
            </ul>
          `;
        } else {
          annotationContainer.innerHTML = `<p class="text-green-600">No annotations found or parsed.</p>`;
        }
    
        if (results.rawScanFindings.length > 0) {
          annotationContainer.innerHTML += `
            <hr class="my-4">
            <h4 class="text-lg font-semibold mb-2 text-gray-700">Raw PDF Scan Findings</h4>
            <ul class="list-disc pl-5 space-y-2">
              ${results.rawScanFindings.map(item => `
                <li class="bg-yellow-50 p-2 rounded">
                  <strong>${this.escapeHtml(item.type)}</strong>:
                  <em>${this.escapeHtml(item.message)}</em>
                  (Severity: ${this.escapeHtml(item.severity)})
                </li>
              `).join('')}
            </ul>
          `;
        }
    
        document.getElementById('metadata').innerHTML = `
          <pre class="whitespace-pre-wrap">
            ${JSON.stringify(results.metadata, null, 2)}
          </pre>
        `;
        document.getElementById('pdfText').value = results.text;
      }
    
      displayStructureAnalysis(structure) {
        let html = '<div class="space-y-4">';
        html += `
          <div class="mb-4">
            <h3 class="font-semibold mb-2">Pages Overview</h3>
            <div class="grid gap-2">
              ${structure.pages.map(page => `
                <div class="p-2 bg-gray-50 rounded">
                  <div class="font-medium">Page ${page.pageNumber}</div>
                  <div class="text-sm">
                    <div>Annotations: ${page.annotations}</div>
                    <div>JavaScript: ${page.hasJavaScript ? 'Yes' : 'No'}</div>
                    <div>Links: ${page.hasLinks ? 'Yes' : 'No'}</div>
                    <div>Actions: ${page.hasActions ? 'Yes' : 'No'}</div>
                  </div>
                </div>
              `).join('')}
            </div>
          </div>
        `;
        html += '</div>';
        document.getElementById('pdfStructure').innerHTML = html;
      }
    
      switchTab(tabId) {
        document.querySelectorAll('.tab-button').forEach(btn => {
          btn.classList.toggle('active', btn.dataset.tab === tabId);
        });
        document.querySelectorAll('.tab-content').forEach(content => {
          content.classList.toggle('hidden', content.id !== `${tabId}Tab`);
        });
      }
    
      escapeHtml(unsafe) {
        return unsafe
          .replace(/&/g, "&amp;")
          .replace(/</g, "&lt;")
          .replace(/>/g, "&gt;")
          .replace(/"/g, "&quot;")
          .replace(/'/g, "&#039;");
      }
    
      formatCategoryName(category) {
        return category
          .replace(/([A-Z])/g, ' $1')
          .replace(/^./, str => str.toUpperCase());
      }
    
      generateReport(results) {
        const report = {
          timestamp: new Date().toISOString(),
          results: results
        };
        const blob = new Blob(
          [JSON.stringify(report, null, 2)],
          { type: 'application/json' }
        );
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `pdf-security-report-${new Date().getTime()}.json`;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);
      }
    }
    
    // --------------------------------------------------------------------------------
    // Initialize UI Handler
    // --------------------------------------------------------------------------------
    const ui = new UIHandler();
  </script>
</body>
</html>
