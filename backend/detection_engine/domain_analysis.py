import re

def extract_domains(text):
    urls = re.findall(r'(https?://[^\s]+)', text)
    domains = []
    for url in urls:
        domain = re.findall(r'https?://([^/]+)/?', url)
        if domain:
            domains.append(domain[0])
    return domains
