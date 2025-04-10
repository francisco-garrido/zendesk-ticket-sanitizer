# Zendesk Ticket Sanitizer

A Python tool for sanitizing Zendesk ticket data by removing sensitive information while preserving vendor-related content.

## Features

- **PII Detection and Removal**:

  - Email addresses → `[EMAIL]`
  - Phone numbers (international formats) → `[PHONE]`
  - Person names → `Person_1`, `Person_2`, etc.
  - Organization names → `Organization_1`, `Organization_2`, etc.
  - Geographic locations → `[GPE]` or `[LOC]`

- **Smart IP Address Handling**:

  - Subnet IPs → `Subnet 1`, `Subnet 2`, etc.
  - Device IPs → `Device IP 1`, `Device IP 2`, etc.
  - Consistent numbering within tickets

- **URL Processing**:

  - Preserves support.auvik.com URLs
  - Converts my.auvik.com entity URLs to `Entity <number>`
  - Preserves vendor URLs (configurable)
  - Other URLs → `[URL]`

- **Additional Features**:
  - Signature removal
  - Vendor name preservation
  - Consistent entity numbering within tickets
  - JSON input/output support

## Prerequisites

Before installing, ensure you have:

- Python 3.7 or higher installed
- pip (Python package installer)
- Ability to install Python packages on your system

## Installation

1. Create a virtual environment:

```bash
python -m venv venv
```

2. Activate the virtual environment:

- Windows:

```bash
.\venv\Scripts\activate
```

- macOS/Linux:

```bash
source venv/bin/activate
```

3. Install dependencies:

```bash
pip install -r requirements.txt
```

4. Install the required spaCy model (REQUIRED - must be done manually):

```bash
python -m spacy download en_core_web_sm
```

**Important Note**: The spaCy model must be installed manually. The script will not automatically download or install it for security reasons. If the model is missing, the script will provide instructions for manual installation.

## Usage

Basic usage:

```bash
python sanitize_zendesk.py input_file.json output_file.json
```

With custom vendor whitelist:

```bash
python sanitize_zendesk.py input_file.json output_file.json --vendor-whitelist path/to/whitelist.txt
```

Enable debug logging:

```bash
python sanitize_zendesk.py input_file.json output_file.json --debug
```

## Input JSON Format

The tool expects a JSON file with Zendesk ticket data in the following format:

```json
{
  "description": "Ticket description text",
  "comments": [
    {
      "body": "Comment text"
    }
  ]
}
```

## Vendor Whitelist

Create a text file with one vendor name per line to customize the vendor whitelist:

```text
Cisco
Palo Alto
Microsoft
AWS
...
```

Default vendors (if no whitelist provided):

- Cisco
- Palo Alto
- Microsoft
- AWS
- Amazon
- Google
- Azure
- VMware
- Oracle
- IBM
- Dell
- HP
- Lenovo

## Examples

### Input Text

```text
John Smith from Acme Corp contacted support about device 192.168.1.100 in subnet 10.0.0.0/24.
Check https://my.auvik.com/dashboard#entity/123456 and https://support.auvik.com/hc/article/12345.
Email: john.smith@acme.com
Phone: +1 (555) 123-4567
```

### Output Text

```text
Person_1 from Organization_1 contacted support about Device IP 1 in Subnet 1.
Check Entity 123456 and https://support.auvik.com/hc/article/12345.
Email: [EMAIL]
Phone: [PHONE]
```

## Command Line Arguments

- `input_file`: Path to input JSON file containing ticket data
- `output_file`: Path to output sanitized JSON file
- `--vendor-whitelist`: Path to vendor whitelist file (optional)
- `--debug`: Enable debug logging (optional)

## Dependencies

- Python 3.7+
- spacy>=3.7.2
- typing-extensions>=4.8.0
- pathlib>=1.0.1
- en_core_web_sm (spaCy model)

## Error Handling

The tool includes comprehensive error handling:

- Invalid JSON input
- Missing spaCy model (provides instructions for manual installation)
- File access errors
- Invalid vendor whitelist

Errors are logged with descriptive messages to help troubleshoot issues.

### Common Issues

1. **Missing spaCy Model**
   If you see an error about missing spaCy model, follow these steps:

   ```bash
   python -m pip install spacy
   python -m spacy download en_core_web_sm
   ```

2. **Permission Issues**
   Ensure you have appropriate permissions to:
   - Create and activate virtual environments
   - Install Python packages
   - Read/write to input and output files
