# PoCForge: From Vulnerability Description to Exploits

## 🎯 Overview

**PoCForge** is a proof-of-concept (PoC) generation tool that combines **Large Language Models (LLMs)** with **on-demand path-sensitive taint analysis** to automatically generate exploits for known vulnerabilities. 

---

## ⚡ How It Works

PoCForge processes vulnerability descriptions to extract critical location information including **file names**, **function names**, and **parameter names**. These elements help identify potential source-to-sink paths:

**Phase 1: Description-Guided Source-to-Sink Localisation** - Uses extracted location information to prioritize candidate sources and identify target vulnerability entries
**Phase 2: Sanitizer-Aware Path Pruning** - Performs feature-string-driven sanitizer evaluation to prune source-to-sink paths
**Phase 3: LLM-Powered Payload Construction** - Analyzes all path constraints using LLMs to generate final exploit payloads
**PoC Assembly** - Organizes all relevant information into complete proof-of-concept exploits

> **📝 Note:** For code confidentiality, the complete source code will be released in this repository (https://github.com/Leousum/POCFORGE) after paper acceptance. Many PoCForge components are currently being utilized in our other research projects.

---

## 🚀 Usage

### ⚙️ 1. Configuration Setup

Edit `config.py` to set up your environment,  Users should focus on the following fields:

```python
MODEL = "<your model>"  # E.g., gpt-4-1106-preview
BASE_URL = "<your base url>"  # E.g., https://api.zhiyungpt.com/v1
API_KEY = "<your api key>"  # API key for your chosen model
GITHUB_TOKEN = "<your github token>"  # Generate at: https://github.com/settings/personal-access-tokens
```

### ⚙️ 2. Environment Requirements

Before getting started, ensure your system meets the following requirements:

- **Python Environment**: 3.8.x or higher
- **Python Dependencies**: Install all required packages using `pip install -r requirements.txt`
- **Java Environment**: OpenJDK 11.0.27 （Mainly for Joern）
- **Joern Environment**: v2.0.293 (Using higher Joern versions may cause runtime failures)

### 📥 3. Input Construction

Create JSON input files for target vulnerabilities. Example for CVE-2023-39360:

```json
{
    "source_id": "CVE-2023-39360",
    "vuln_type": "xss",
    "description": "Cacti is an open source operational monitoring and fault management framework...",
    "source_link": "https://nvd.nist.gov/vuln/detail/CVE-2023-39360",
    "git_links": ["https://github.com/Cacti/cacti"],
    "affected_version": ["cpe:2.3:a:cacti:cacti:1.2.24:*:*:*:*:*:*:*"]
}
```

#### 📋 Field Descriptions:

- **`source_id`**: Vulnerability identifier (preferably CVE ID)
- **`vuln_type`**: Vulnerability type (must match `VulnType` enum in `config.py`)
- **`description`**: Vulnerability description from NVD or enhanced with location hints
- **`git_links`**: Repository URLs (automatically cloned to `REPO_ROOT`)
- **`affected_version`**: Vulnerable versions (CPE format or version numbers)

**📁 File Location:** Save JSON files in the directory specified by `INPUT_ROOT`

### 🚀 4. Script Execution

Run the main script to generate PoCs:

```bash
python3 autopoc.py
```

The script automatically processes all JSON files in the `INPUT_ROOT` directory. Modify `autopoc.py` to target specific vulnerabilities using the `generate_poc` method ( **Output Result** : The return value of this method is the final generated PoC).

---

## 🏆 Assigned CVEs

- CVE-2024-48622
- CVE-2024-48623  
- CVE-2024-48624
- CVE-2024-52701
- CVE-2024-52702

---

## 📞 Contact

For questions and support, please open an issue.