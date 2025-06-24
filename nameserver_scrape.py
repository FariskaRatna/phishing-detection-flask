import dns.resolver
from urllib.parse import urlparse

def get_nameservers(url):
    # Ekstrak domain dari URL
    domain = urlparse(url).netloc
    # Hapus www jika ada
    if domain.startswith("www."):
        domain = domain[4:]

    try:
        answers = dns.resolver.resolve(domain, 'NS')
        nameservers = [rdata.to_text() for rdata in answers]
        return nameservers
    except Exception as e:
        return f"Error: {e}"

# Contoh penggunaan
# url = "https://openrouter.ai/docs/faq#what-purchase-options-exist"
# print(get_nameservers(url))
