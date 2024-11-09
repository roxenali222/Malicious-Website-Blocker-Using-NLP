from urllib.parse import urlparse
import re
from tld import get_tld
def having_ip_address(url):
    # Check if the URL contains an IP address
    ip_pattern = re.compile(
        '(([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.'
        '([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\/)|'  # IPv4
        '((0x[0-9a-fA-F]{1,2})\\.(0x[0-9a-fA-F]{1,2})\\.(0x[0-9a-fA-F]{1,2})\\.(0x[0-9a-fA-F]{1,2})\\/)' # IPv4 in hexadecimal
        '(?:[a-fA-F0-9]{1,4}:){7}[a-fA-F0-9]{1,4}'  # Ipv6
    )
    if ip_pattern.search(url):
        return 1
    else:
        return 0

def count_dots(url):
    return url.count('.')

def count_hyphens(url):
    return url.count('-')

def count_question_marks(url):
    return url.count('?')

def count_equals(url):
    return url.count('=')

def count_at(url):
    return url.count('@')

def count_slashes(url):
    return url.count('/')

def count_colons(url):
    return url.count(':')

def count_http(url):
    return url.lower().count('http')

def count_https(url):
    return url.lower().count('https')

def url_length(url):
    return len(url)

def hostname_length(url):
    return len(urlparse(url).netloc)

def path_length(url):
    return len(urlparse(url).path)

def query_length(url):
    return len(urlparse(url).query)

def count_subdomains(url):
    # Count the number of subdomains in the URL
    return url.count('.') - 1  # Assuming 'www.' is not considered a subdomain

def get_tld_length(url):
    # Get the length of the top-level domain
    try:
        tld = get_tld(url, as_object=True).fld
        return len(tld)
    except:
        return -1  # In case of an error, such as when the TLD can't be extracted

def suspicious_words_in_url(url):
    # Check for the presence of suspicious words
    suspicious_words = ['PayPal|login|signin|bank|account|update|free|lucky|service|bonus|ebayisapi|webscr']
    return any(word in url.lower() for word in suspicious_words)

def digit_count(url):
    # Count the number of digits in the URL
    return sum(c.isdigit() for c in url)

def letter_count(url):
    # Count the number of letters in the URL
    return sum(c.isalpha() for c in url)
def uses_shortening_service(url):
    # Check if the URL uses a known shortening service
    shortening_services = [
        'bit.ly', 'goo.gl', 'shorte.st', 'go2l.ink', 'x.co', 'ow.ly', 't.co', 'tinyurl', 'tr.im', 'is.gd', 'cli.gs',
        'yfrog.com', 'migre.me', 'ff.im', 'tiny.cc', 'url4.eu', 'twit.ac', 'su.pr', 'twurl.nl', 'snipurl.com',
        'short.to', 'BudURL.com', 'ping.fm', 'post.ly', 'Just.as', 'bkite.com', 'snipr.com', 'fic.kr', 'loopt.us',
        'doiop.com', 'short.ie', 'kl.am', 'wp.me', 'rubyurl.com', 'om.ly', 'to.ly', 'bit.do', 'lnkd.in',
        'db.tt', 'qr.ae', 'adf.ly', 'goo.gl', 'bitly.com', 'cur.lv', 'tinyurl.com', 'ow.ly', 'bit.ly', 'ity.im',
        'q.gs', 'is.gd', 'po.st', 'bc.vc', 'twitthis.com', 'u.to', 'j.mp', 'buzurl.com', 'cutt.us', 'u.bb', 'yourls.org',
        'x.co', 'prettylinkpro.com', 'scrnch.me', 'filoops.info', 'vzturl.com', 'qr.net', '1url.com', 'tweez.me', 'v.gd',
        'tr.im', 'link.zip.net'
]

    return any(service in url for service in shortening_services)

def special_char_count(url):
    # Count the number of special characters in the URL
    special_chars = [';', '&', '$', '%', '#', '@', '!', '*']
    return sum(url.count(char) for char in special_chars)

def preprocess_url(url):
    features = [
        having_ip_address(url),
        count_dots(url),
        count_hyphens(url),
        count_question_marks(url),
        count_equals(url),
        count_at(url),
        count_slashes(url),
        count_colons(url),
        count_http(url),
        count_https(url),
        url_length(url),
        hostname_length(url),
        path_length(url),
        query_length(url),
        count_subdomains(url),
        get_tld_length(url),
        1 if suspicious_words_in_url(url) else 0,
        digit_count(url),
        letter_count(url),
        1 if uses_shortening_service(url) else 0,
        special_char_count(url)
    ]
    return features