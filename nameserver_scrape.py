import dns.resolver
from urllib.parse import urlparse
import tldextract

def get_nameservers(url):
    try:
        # Extract domain from URL using tldextract for better handling
        extracted = tldextract.extract(url)
        domain = f"{extracted.domain}.{extracted.suffix}"
        
        # If no domain extracted, try urlparse as fallback
        if not domain or domain == '.':
            parsed = urlparse(url)
            domain = parsed.netloc
            # Remove www if present
            if domain and domain.startswith("www."):
                domain = domain[4:]
        
        # If still no domain, return empty list
        if not domain or domain == '.':
            return []
        
        # Resolve nameservers
        answers = dns.resolver.resolve(domain, 'NS')
        nameservers = [rdata.to_text() for rdata in answers]
        return nameservers
        
    except Exception as e:
        # Return empty list instead of error string to maintain consistent return type
        return []

# Contoh penggunaan
# url = "https://openrouter.ai/docs/faq#what-purchase-options-exist"
# print(get_nameservers(url))
