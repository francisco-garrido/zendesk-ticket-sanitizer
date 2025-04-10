# Zendesk Ticket Sanitizer

A Python-based CLI tool that sanitizes Zendesk ticket data by removing personally identifiable information (PII) while preserving important technical context.

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

## Installation

1. Clone this repository:

```bash
git clone <repository-url>
cd <repository-directory>
```

2. Create and activate a virtual environment (recommended):

```bash
# Windows
python -m venv venv
.\venv\Scripts\activate

# Linux/MacOS
python -m venv venv
source venv/bin/activate
```

3. Install required dependencies:

```bash
pip install spacy
python -m spacy download en_core_web_sm
```

## Usage

### Basic Usage

```bash
python sanitize_zendesk.py input.json output.json
```

### Advanced Usage

```bash
# With debug logging
python sanitize_zendesk.py input.json output.json --debug

# With custom vendor whitelist
python sanitize_zendesk.py input.json output.json --vendor-whitelist vendors.txt
```

### Input JSON Format

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

### Vendor Whitelist

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

- Python 3.6+
- spaCy
- en_core_web_sm (spaCy model)

## Error Handling

The tool includes comprehensive error handling:

- Invalid JSON input
- Missing spaCy model (auto-installs if missing)
- File access errors
- Invalid vendor whitelist

Errors are logged with descriptive messages to help troubleshoot issues.
