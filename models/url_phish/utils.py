import joblib
from urllib.parse import urlparse
import pandas as pd
import tldextract
from nltk.tokenize import RegexpTokenizer

model = joblib.load("models/url_phish/model.pkl")

def parse_url(url):
    try:
        no_scheme = not url.startswith('https://') and not url.startswith('http://')
        if no_scheme:
            parsed_url = urlparse(f"http://{url}")
            return {
                "scheme": None, # not established a value for this
                "netloc": parsed_url.netloc,
                "path": parsed_url.path,
                "params": parsed_url.params,
                "query": parsed_url.query,
                "fragment": parsed_url.fragment,
            }
        else:
            parsed_url = urlparse(url)
            return {
                "scheme": parsed_url.scheme,
                "netloc": parsed_url.netloc,
                "path": parsed_url.path,
                "params": parsed_url.params,
                "query": parsed_url.query,
                "fragment": parsed_url.fragment,
            }
    except:
        return None
    
def is_url_phishing(url):
    df = pd.DataFrame({"url": [url]})
    df["parsed_url"] = df.url.apply(parse_url)
    df = pd.concat([
        df.drop(['parsed_url'], axis=1),
        df['parsed_url'].apply(pd.Series)
    ], axis=1)
    
    df = df[~df.netloc.isnull()]
    df["length"] = df.url.str.len()
    df["tld"] = df.netloc.apply(lambda nl: tldextract.extract(nl).suffix)
    df['tld'] = df['tld'].replace('','None')
    df["is_ip"] = df.netloc.str.fullmatch(r"\d+\.\d+\.\d+\.\d+")
    df['domain_hyphens'] = df.netloc.str.count('-')
    df['domain_underscores'] = df.netloc.str.count('_')
    df['path_hyphens'] = df.path.str.count('-')
    df['path_underscores'] = df.path.str.count('_')
    df['slashes'] = df.path.str.count('/')
    df['full_stops'] = df.path.str.count('.')
    
    def get_num_subdomains(netloc: str) -> int:
        subdomain = tldextract.extract(netloc).subdomain 
        if subdomain == "":
            return 0
        return subdomain.count('.') + 1
    
    df['num_subdomains'] = df['netloc'].apply(lambda net: get_num_subdomains(net))
    
    tokenizer = RegexpTokenizer(r'[A-Za-z]+')
    def tokenize_domain(netloc: str) -> str:
        split_domain = tldextract.extract(netloc)
        no_tld = str(split_domain.subdomain +'.'+ split_domain.domain)
        return " ".join(map(str,tokenizer.tokenize(no_tld)))
             
    df['domain_tokens'] = df['netloc'].apply(lambda net: tokenize_domain(net))
    df['path_tokens'] = df['path'].apply(lambda path: " ".join(map(str,tokenizer.tokenize(path))))
    
    df.drop('url', axis=1, inplace=True)
    df.drop('scheme', axis=1, inplace=True)
    df.drop('netloc', axis=1, inplace=True)
    df.drop('path', axis=1, inplace=True)
    df.drop('params', axis=1, inplace=True)
    df.drop('query', axis=1, inplace=True)
    df.drop('fragment', axis=1, inplace=True)

    return model.predict(df)[0] == "bad"