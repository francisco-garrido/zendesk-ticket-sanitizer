import argparse
import json
import re
import spacy
from typing import Dict, List, Set, Union
import logging
from pathlib import Path
from collections import defaultdict

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class TicketSanitizer:
    def __init__(self, vendor_whitelist_path: str = None):
        """Initialize the ticket sanitizer with optional vendor whitelist."""
        # Load spaCy model for NER
        try:
            self.nlp = spacy.load("en_core_web_sm")
        except OSError:
            logger.error("SpaCy model not found. Please install it using:")
            logger.error("python -m pip install spacy")
            logger.error("python -m spacy download en_core_web_sm")
            raise OSError(
                "Required spaCy model 'en_core_web_sm' is not installed. "
                "Please install it manually using the commands shown in the error log."
            )

        # Load vendor whitelist if provided
        self.vendor_whitelist = self._load_vendor_whitelist(vendor_whitelist_path)

        # Initialize counters and mappings
        self.reset_counters()

    def reset_counters(self):
        """Reset all counters and mappings for a new ticket."""
        self.subnet_counter = 0
        self.device_ip_counter = 0
        self.person_counter = 0
        self.org_counter = 0
        self.ip_mapping = {}
        self.person_mapping = {}
        self.org_mapping = {}

        # Compile regex patterns - optimized for common PII patterns
        self.patterns = {
            'email': re.compile(r'\b[\w._%+-]+@[\w.-]+\.[A-Za-z]{2,}\b'),  # Simplified email pattern
            'phone': re.compile(
                r'\b(?:'  # Start of phone pattern
                r'(?:\+\d{1,2}[\s.-]?)?'  # Optional country code
                r'(?:\(?\d{3}\)?[\s.-]?\d{3}[\s.-]?\d{4}|'  # US/Canada format
                r'\d{2,4}[\s.-]?\d{2,4}[\s.-]?\d{2,4})'  # International format
                r')\b'
            ),
            'subnet': re.compile(r'\b(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(?:\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)){3}/\d{1,2}\b'),  # CIDR notation
            'device_ip': re.compile(r'\b(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(?:\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)){3}\b'),  # IPv4 address
            'auvik_entity': re.compile(r'https?://my\.auvik\.com/[^#]*#entity/(\d+)(?:[^\s]*)?'),  # Auvik entity URL
            'auvik_support': re.compile(r'https?://support\.auvik\.com/[^\s]+'),  # Auvik support URL
            'url': re.compile(r'https?://(?:[\w-]|(?:%[0-9a-fA-F]{2}))+(?::\d+)?(?:/[^/\s]*)*'),  # Other URLs
            'signature': re.compile(
                r'(?i)(?:^|\n)[\s]*'  # Start of line or after newline
                r'(?:best regards|sincerely|thanks|thank you|regards|cheers|\bBR\b)'
                r'[\s,]*'  # Optional spaces or comma
                r'(?:[A-Z][a-z]+(?:\s+[A-Z][a-z]+)*)?'  # Optional name after signature
                r'.*$',  # Rest of the line
                re.MULTILINE
            )
        }

    def _load_vendor_whitelist(self, whitelist_path: str = None) -> Set[str]:
        """Load vendor whitelist from file or use default."""
        default_vendors = {
            'Cisco', 'Palo Alto', 'Meraki', 'Microsoft', 'AWS', 'Amazon', 'Google',
            'Azure', 'VMware', 'Oracle', 'IBM', 'Dell', 'HP', 'Lenovo', 'Ubiquiti',
        }
        
        if not whitelist_path:
            return default_vendors

        try:
            with open(whitelist_path, 'r') as f:
                vendors = set(line.strip() for line in f if line.strip())
            return vendors | default_vendors
        except Exception as e:
            logger.warning(f"Could not load vendor whitelist: {e}. Using default.")
            return default_vendors

    def _is_vendor(self, text: str) -> bool:
        """Check if text matches any vendor in whitelist."""
        text_lower = text.lower()
        return any(vendor.lower() in text_lower for vendor in self.vendor_whitelist)

    def _get_ip_placeholder(self, ip: str, is_subnet: bool = False) -> str:
        """Get a consistent placeholder for an IP address."""
        if ip in self.ip_mapping:
            return self.ip_mapping[ip]

        if is_subnet:
            self.subnet_counter += 1
            placeholder = f"Subnet {self.subnet_counter}"
        else:
            self.device_ip_counter += 1
            placeholder = f"Device IP {self.device_ip_counter}"

        self.ip_mapping[ip] = placeholder
        return placeholder

    def _get_entity_placeholder(self, entity_text: str, entity_type: str) -> str:
        """Get a consistent placeholder for a named entity."""
        if entity_type == 'PERSON':
            if entity_text in self.person_mapping:
                return self.person_mapping[entity_text]
            self.person_counter += 1
            placeholder = f"Person_{self.person_counter}"
            self.person_mapping[entity_text] = placeholder
            return placeholder
        elif entity_type == 'ORG':
            if entity_text in self.org_mapping:
                return self.org_mapping[entity_text]
            self.org_counter += 1
            placeholder = f"Organization_{self.org_counter}"
            self.org_mapping[entity_text] = placeholder
            return placeholder
        else:
            return f"[{entity_type}]"

    def _sanitize_with_regex(self, text: str) -> str:
        """Apply regex-based sanitization."""
        if not text:
            return text

        # Replace emails
        text = self.patterns['email'].sub('[EMAIL]', text)
        
        # Replace phone numbers
        text = self.patterns['phone'].sub('[PHONE]', text)
        
        # Handle Auvik support URLs (preserve these)
        text = self.patterns['auvik_support'].sub(lambda m: m.group(), text)
        
        # Handle Auvik entity URLs
        text = self.patterns['auvik_entity'].sub(
            lambda m: f"Entity {m.group(1)}", 
            text
        )
        
        # Replace subnet IPs
        text = self.patterns['subnet'].sub(
            lambda m: self._get_ip_placeholder(m.group(), is_subnet=True),
            text
        )
        
        # Replace device IPs
        text = self.patterns['device_ip'].sub(
            lambda m: self._get_ip_placeholder(m.group(), is_subnet=False),
            text
        )
        
        # Replace remaining URLs (preserve vendor URLs)
        text = self.patterns['url'].sub(
            lambda m: m.group() if self._is_vendor(m.group()) else '[URL]',
            text
        )
        
        # Remove signatures
        text = self.patterns['signature'].sub('', text)
        
        return text

    def _sanitize_with_nlp(self, text: str) -> str:
        """Apply NLP-based sanitization using spaCy."""
        if not text:
            return text

        doc = self.nlp(text)
        sanitized_text = text
        
        # Collect all entities to replace
        entities_to_replace = []
        for ent in doc.ents:
            # Skip vendor names
            if self._is_vendor(ent.text):
                continue
                
            # Handle different entity types
            if ent.label_ in {'PERSON', 'ORG'}:
                placeholder = self._get_entity_placeholder(ent.text, ent.label_)
                entities_to_replace.append((ent.text, placeholder))
            elif ent.label_ in {'GPE', 'LOC'}:
                entities_to_replace.append((ent.text, f"[{ent.label_}]"))
        
        # Sort entities by length (descending) to avoid nested replacements
        entities_to_replace.sort(key=lambda x: len(x[0]), reverse=True)
        
        # Replace entities
        for original, replacement in entities_to_replace:
            sanitized_text = sanitized_text.replace(original, replacement)
        
        return sanitized_text

    def sanitize_ticket(self, ticket_data: Union[str, Dict]) -> Dict:
        """Sanitize a Zendesk ticket."""
        if isinstance(ticket_data, str):
            try:
                ticket_data = json.loads(ticket_data)
            except json.JSONDecodeError:
                raise ValueError("Invalid JSON string provided")

        # Reset counters for each ticket
        self.reset_counters()

        # Deep copy to avoid modifying original
        sanitized_data = ticket_data.copy()

        # Handle Zendesk API format
        if 'ticket' in sanitized_data:
            ticket = sanitized_data['ticket']
            
            # Sanitize subject
            if 'subject' in ticket:
                ticket['subject'] = self._sanitize_with_regex(ticket['subject'])
                ticket['subject'] = self._sanitize_with_nlp(ticket['subject'])

            # Sanitize description
            if 'description' in ticket:
                ticket['description'] = self._sanitize_with_regex(ticket['description'])
                ticket['description'] = self._sanitize_with_nlp(ticket['description'])

            # Sanitize requester info
            if 'requester' in ticket:
                if 'name' in ticket['requester']:
                    original_name = ticket['requester']['name']
                    ticket['requester']['name'] = self._get_entity_placeholder(original_name, 'PERSON')
                if 'email' in ticket['requester']:
                    ticket['requester']['email'] = '[EMAIL]'

            # Sanitize assignee info
            if 'assignee' in ticket:
                if 'name' in ticket['assignee']:
                    original_name = ticket['assignee']['name']
                    ticket['assignee']['name'] = self._get_entity_placeholder(original_name, 'PERSON')
                if 'email' in ticket['assignee']:
                    ticket['assignee']['email'] = '[EMAIL]'

        # Sanitize comments
        if 'comments' in sanitized_data:
            comments_data = sanitized_data['comments'].get('comments', [])
            for comment in comments_data:
                if isinstance(comment, dict):
                    # Sanitize comment body
                    if 'body' in comment:
                        comment['body'] = self._sanitize_with_regex(comment['body'])
                        comment['body'] = self._sanitize_with_nlp(comment['body'])
                    
                    # Sanitize author info
                    if 'author' in comment:
                        if 'name' in comment['author']:
                            original_name = comment['author']['name']
                            comment['author']['name'] = self._get_entity_placeholder(original_name, 'PERSON')
                        if 'email' in comment['author']:
                            comment['author']['email'] = '[EMAIL]'

        return sanitized_data

def main():
    parser = argparse.ArgumentParser(description='Sanitize Zendesk ticket data')
    parser.add_argument('input_file', help='Path to input JSON file containing ticket data')
    parser.add_argument('output_file', help='Path to output sanitized JSON file')
    parser.add_argument('--vendor-whitelist', help='Path to vendor whitelist file')
    parser.add_argument('--debug', action='store_true', help='Enable debug logging')

    args = parser.parse_args()

    if args.debug:
        logger.setLevel(logging.DEBUG)

    try:
        # Initialize sanitizer
        sanitizer = TicketSanitizer(args.vendor_whitelist)

        # Read input file
        with open(args.input_file, 'r', encoding='utf-8') as f:
            ticket_data = json.load(f)

        # Sanitize ticket
        sanitized_data = sanitizer.sanitize_ticket(ticket_data)

        # Write output
        with open(args.output_file, 'w', encoding='utf-8') as f:
            json.dump(sanitized_data, f, indent=2, ensure_ascii=False)

        logger.info(f"Successfully sanitized ticket data and saved to {args.output_file}")

    except Exception as e:
        logger.error(f"Error processing ticket: {str(e)}")
        raise

if __name__ == "__main__":
    main()
