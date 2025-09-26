
from flask import Flask, request, jsonify, Response
import os
import json
import logging
import re
import random
import time
import requests
from urllib.parse import urlparse, parse_qs

app = Flask(__name__)

# Configuration and constants... (same as before)
REQUEST_TIMEOUT = 30
MAX_RETRIES = 3
RETRY_DELAY = 2
PORT = 3000
SUPPORTED_DOMAINS = ["terabox.com", "1024terabox.com", "teraboxapp.com", "teraboxlink.com", "terasharelink.com", "terafileshare.com", "www.1024tera.com", "1024tera.com", "1024tera.cn", "teraboxdrive.com", "dubox.com"]
TERABOX_URL_REGEX = r'^https:\/\/(www\.)?(' + '|'.join(re.escape(d) for d in SUPPORTED_DOMAINS) + r')\/(s|sharing\/link)\/[A-Za-z0-9_\-]+'
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)
HEADERS = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:135.0) Gecko/20100101 Firefox/135.0', 'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8', 'Accept-Language': 'en-US,en;q=0.5', 'Connection': 'keep-alive', 'Upgrade-Insecure-Requests': '1', 'Sec-Fetch-Dest': 'document', 'Sec-Fetch-Mode': 'navigate', 'Sec-Fetch-Site': 'none', 'Sec-Fetch-User': '?1', 'Priority': 'u=0, i'}

def get_cookies():
    env_cookie_string = os.environ.get('TERABOX_COOKIE')
    if env_cookie_string:
        logger.info("Using cookie from environment variable.")
        try:
            return {cookie.split('=')[0].strip(): cookie.split('=', 1)[1].strip() for cookie in env_cookie_string.split(';')}
        except Exception:
            logger.error("Failed to parse TERABOX_COOKIE environment variable. Falling back to hardcoded cookies.")
    
    logger.warning("Using hardcoded fallback cookie. This may not be reliable.")
    return {
        'ndut_fmt': '082E0D57C65BDC31F6FF293F5D23164958B85D6952CCB6ED5D8A3870CB302BE7',
        'ndus': 'Y-wWXKyteHuigAhC03Fr4bbee-QguZ4JC6UAdqap',
        'browserid': 'veWFJBJ9hgVgY0eI9S7yzv66aE28f3als3qUXadSjEuICKF1WWBh4inG3KAWJsAYMkAFpH2FuNUum87q',
        'csrfToken': 'wlv_WNcWCjBtbNQDrHSnut2h',
        'lang': 'en',
        'PANWEB': '1'
    }

def validate_terabox_url(url):
    return re.match(TERABOX_URL_REGEX, url) is not None

def make_request(url, method='GET', headers=None, params=None, allow_redirects=True, cookies=None):
    session = requests.Session()
    retries = 0
    while retries < MAX_RETRIES:
        try:
            response = session.request(method, url, headers=headers or HEADERS, params=params, cookies=cookies, allow_redirects=allow_redirects, timeout=REQUEST_TIMEOUT)
            if response.status_code in [403, 429, 503]:
                time.sleep(RETRY_DELAY * (2 ** retries))
                retries += 1
                continue
            response.raise_for_status()
            return response
        except (requests.ConnectionError, requests.Timeout) as e:
            logger.warning(f"Connection error: {str(e)}, retrying...")
            time.sleep(RETRY_DELAY * (2 ** retries))
            retries += 1
    raise Exception("Max retries exceeded.")

def find_between(string, start, end):
    try:
        start_index = string.index(start) + len(start)
        end_index = string.index(end, start_index)
        return string[start_index:end_index]
    except ValueError:
        return None

def extract_tokens(html):
    js_token = find_between(html, 'fn("', '")')
    if not js_token:
        js_token = find_between(html, "fn('", "')")
    log_id_match = re.search(r'dp-logid=([^&"]+)', html)
    log_id = log_id_match.group(1) if log_id_match else None
    if not js_token or not log_id:
        raise Exception("Could not extract jsToken or log_id")
    return js_token, log_id

def get_surl(response_url):
    surl_match = re.search(r'/(s|sharing/link)/([A-Za-z0-9_\-]+)', response_url)
    if surl_match:
        return surl_match.group(2)
    raise Exception("Could not extract surl from URL")

def get_direct_link(url, cookies):
    try:
        response = make_request(url, method='HEAD', allow_redirects=False, cookies=cookies)
        return response.headers.get('Location', url)
    except Exception:
        return url

def process_terabox_url(url):
    current_cookies = get_cookies()
    response = make_request(url, cookies=current_cookies)
    html = response.text
    js_token, log_id = extract_tokens(html)
    surl = get_surl(response.url)
    
    params = {'app_id': '250528', 'web': '1', 'channel': 'dubox', 'clienttype': '0', 'jsToken': js_token, 'dplogid': log_id, 'page': '1', 'num': '20', 'order': 'time', 'desc': '1', 'site_referer': response.url, 'shorturl': surl, 'root': '1'}
    
    api_url = f"https://{urlparse(url).netloc}/share/list"
    response2 = make_request(api_url, params=params, cookies=current_cookies)
    response_data2 = response2.json()
    
    if 'list' not in response_data2 or not response_data2['list']:
        raise Exception("No files found in shared link")
    
    file_list = response_data2['list']
    
    if file_list and file_list[0].get('isdir') == "1":
        folder_params = params.copy()
        folder_params.update({'dir': file_list[0]['path'], 'order': 'asc', 'by': 'name'})
        folder_params.pop('desc', None); folder_params.pop('root', None)
        folder_response = make_request(api_url, params=folder_params, cookies=current_cookies)
        folder_data = folder_response.json()
        if 'list' in folder_data and folder_data['list']:
            file_list = [item for item in folder_data['list'] if item.get('isdir') != "1"]

    results = []
    for file in file_list:
        if file.get('isdir') == "1": continue
        dlink = file.get('dlink', '')
        if not dlink: continue
        direct_link = get_direct_link(dlink, current_cookies)
        size_bytes = file.get('size', 0)
        try:
            size_bytes = int(size_bytes)
            if size_bytes >= 1024**3: size_str = f"{size_bytes / 1024**3:.2f} GB"
            elif size_bytes >= 1024**2: size_str = f"{size_bytes / 1024**2:.2f} MB"
            else: size_str = f"{size_bytes / 1024:.2f} KB"
        except (ValueError, TypeError): size_str = "Unknown"
        
        results.append({"file_name": file.get("server_filename", "Unknown"), "size": size_str, "size_bytes": size_bytes, "download_url": direct_link})
    
    return results

@app.route('/', defaults={'path': ''})
@app.route('/<path:path>')
def catch_all(path):
    url = request.args.get('url')
    if not url:
        return jsonify({"status": "API Running", "usage": "/api?url=TERABOX_SHARE_URL"})
    if not validate_terabox_url(url):
        return jsonify({"status": "error", "message": "Invalid Terabox URL format"}), 400
    try:
        files = process_terabox_url(url)
        if not files:
            return jsonify({"status": "error", "message": "No downloadable files found"}), 404
        return jsonify({"status": "success", "url": url, "files": files, "file_count": len(files)})
    except Exception as e:
        logger.error(f"API error for url {url}: {str(e)}")
        return jsonify({"status": "error", "message": str(e)}), 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=int(os.environ.get("PORT", 3000)))
