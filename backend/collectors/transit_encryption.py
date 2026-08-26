import re
import logging

logger = logging.getLogger(__name__)

class TransitObfuscator:
    """
    A utility class to obfuscate (mask) and deobfuscate (unmask) sensitive terms 
    (like database table names, ARNs, and PII) before they are sent over the network 
    to third-party APIs (e.g., LLMs), and restore them when the response is received.
    """
    
    def __init__(self, prefix="ENC_"):
        self.mapping = {}
        self.reverse_mapping = {}
        self.prefix = prefix
        self.counter = 1

    def mask_terms(self, text: str, terms_to_mask: list[str]) -> str:
        """
        Replaces sensitive terms in the input text with unique encryption tokens.
        Longer terms are processed first to prevent partial masking.
        """
        if not text or not terms_to_mask:
            return text
            
        # Sort by length descending to replace full ARNs before partial matches
        terms_to_mask = sorted(list(set(terms_to_mask)), key=len, reverse=True)
        masked_text = text
        
        for term in terms_to_mask:
            term = str(term)
            if not term or len(term.strip()) < 3:
                continue  # Skip trivial terms to prevent aggressive over-masking
                
            if term not in self.mapping:
                token = f"{self.prefix}{self.counter:04d}"
                self.counter += 1
                self.mapping[term] = token
                self.reverse_mapping[token] = term
            
            masked_text = masked_text.replace(term, self.mapping[term])
            
        return masked_text

    def unmask_text(self, text: str) -> str:
        """
        Restores the unique encryption tokens back to their original sensitive terms.
        """
        if not text:
            return text
            
        unmasked_text = text
        for token, original in sorted(self.reverse_mapping.items(), key=lambda x: len(x[0]), reverse=True):
            unmasked_text = unmasked_text.replace(token, original)
            
        return unmasked_text
        
    @staticmethod
    def extract_sensitive_data(data) -> list[str]:
        """
        Recursively extracts sensitive strings (ARNs, UUIDs, Emails, AWS Account IDs, GCP projects)
        from strings, lists, or dicts so they can be masked.
        """
        sensitive_terms = []
        
        uuid_pattern = re.compile(r'\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b', re.IGNORECASE)
        email_pattern = re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,7}\b')
        aws_account_pattern = re.compile(r'\b\d{12}\b')

        if isinstance(data, str):
            # Check for ARNs and GCP identifiers
            if data.startswith("arn:") or data.startswith("projects/") or "::" in data or "gcp:role" in data:
                sensitive_terms.append(data)
                
            # Extract UUIDs (e.g. Supabase IDs, clerk_ids, scan_ids)
            sensitive_terms.extend(uuid_pattern.findall(data))
            
            # Extract Emails
            sensitive_terms.extend(email_pattern.findall(data))
            
            # Extract AWS Account IDs
            sensitive_terms.extend(aws_account_pattern.findall(data))
            
        elif isinstance(data, list):
            for item in data:
                sensitive_terms.extend(TransitObfuscator.extract_sensitive_data(item))
                
        elif isinstance(data, dict):
            for v in data.values():
                sensitive_terms.extend(TransitObfuscator.extract_sensitive_data(v))
                
        return list(set(sensitive_terms))
