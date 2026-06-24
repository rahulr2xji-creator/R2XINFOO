import asyncio
import time
import httpx
import json
from collections import defaultdict
from functools import wraps
from flask import Flask, request, jsonify
from flask_cors import CORS
from cachetools import TTLCache
from typing import Tuple
from proto import FreeFire_pb2, main_pb2, AccountPersonalShow_pb2
from google.protobuf import json_format, message
from google.protobuf.message import Message
from Crypto.Cipher import AES
import base64

# === Settings ===

MAIN_KEY = base64.b64decode('WWcmdGMlREV1aDYlWmNeOA==')
MAIN_IV = base64.b64decode('Nm95WkRyMjJFM3ljaGpNJQ==')
RELEASEVERSION = "OB54"
USERAGENT = "Dalvik/2.1.0 (Linux; U; Android 13; CPH2095 Build/RKQ1.211119.001)"
SUPPORTED_REGIONS = {"IND", "BR", "US", "SAC", "NA", "SG", "RU", "ID", "TW", "VN", "TH", "ME", "PK", "CIS", "BD", "EUROPE"}

# Updated account credentials for each region
REGION_CREDENTIALS = {
    "IND": {"uid": "4797885396", "password": "M4X_BY_SEMY_km11H3EV"},
    "BR": {"uid": "14379387726", "password": "69B3A41D5D68C593161A84CBC8966884AA763144A58CEF9A95D226EB853B53FF"},
    "US": {"uid": "14379387726", "password": "69B3A41D5D68C593161A84CBC8966884AA763144A58CEF9A95D226EB853B53FF"},
    "SAC": {"uid": "14379387726", "password": "69B3A41D5D68C593161A84CBC8966884AA763144A58CEF9A95D226EB853B53FF"},
    "NA": {"uid": "14379387726", "password": "69B3A41D5D68C593161A84CBC8966884AA763144A58CEF9A95D226EB853B53FF"},
    "SG": {"uid": "14379387726", "password": "69B3A41D5D68C593161A84CBC8966884AA763144A58CEF9A95D226EB853B53FF"},
    "RU": {"uid": "14379387726", "password": "69B3A41D5D68C593161A84CBC8966884AA763144A58CEF9A95D226EB853B53FF"},
    "ID": {"uid": "14379387726", "password": "69B3A41D5D68C593161A84CBC8966884AA763144A58CEF9A95D226EB853B53FF"},
    "TW": {"uid": "14379387726", "password": "69B3A41D5D68C593161A84CBC8966884AA763144A58CEF9A95D226EB853B53FF"},
    "VN": {"uid": "14379387726", "password": "69B3A41D5D68C593161A84CBC8966884AA763144A58CEF9A95D226EB853B53FF"},
    "TH": {"uid": "14379387726", "password": "69B3A41D5D68C593161A84CBC8966884AA763144A58CEF9A95D226EB853B53FF"},
    "ME": {"uid": "14379387726", "password": "69B3A41D5D68C593161A84CBC8966884AA763144A58CEF9A95D226EB853B53FF"},
    "PK": {"uid": "14379387726", "password": "69B3A41D5D68C593161A84CBC8966884AA763144A58CEF9A95D226EB853B53FF"},
    "CIS": {"uid": "14379387726", "password": "69B3A41D5D68C593161A84CBC8966884AA763144A58CEF9A95D226EB853B53FF"},
    "BD": {"uid": "14379387726", "password": "69B3A41D5D68C593161A84CBC8966884AA763144A58CEF9A95D226EB853B53FF"},
    "EUROPE": {"uid": "14379387726", "password": "69B3A41D5D68C593161A84CBC8966884AA763144A58CEF9A95D226EB853B53FF"}
}

# Server URLs for each region
REGION_SERVERS = {
    "IND": "https://client.ind.freefiremobile.com",
    "BR": "https://client.br.freefiremobile.com",
    "US": "https://client.us.freefiremobile.com",
    "SAC": "https://client.sac.freefiremobile.com",
    "NA": "https://client.na.freefiremobile.com",
    "SG": "https://client.sg.freefiremobile.com",
    "RU": "https://client.ru.freefiremobile.com",
    "ID": "https://client.id.freefiremobile.com",
    "TW": "https://client.tw.freefiremobile.com",
    "VN": "https://client.vn.freefiremobile.com",
    "TH": "https://client.th.freefiremobile.com",
    "ME": "https://client.me.freefiremobile.com",
    "PK": "https://client.pk.freefiremobile.com",
    "CIS": "https://client.cis.freefiremobile.com",
    "BD": "https://client.bd.freefiremobile.com",
    "EUROPE": "https://client.europe.freefiremobile.com"
}

# === Flask App Setup ===

app = Flask(__name__)
CORS(app)
cache = TTLCache(maxsize=100, ttl=300)
cached_tokens = defaultdict(dict)
uid_region_cache = {}

# === Helper Functions ===

def pad(text: bytes) -> bytes:
    padding_length = AES.block_size - (len(text) % AES.block_size)
    return text + bytes([padding_length] * padding_length)

def aes_cbc_encrypt(key: bytes, iv: bytes, plaintext: bytes) -> bytes:
    aes = AES.new(key, AES.MODE_CBC, iv)
    return aes.encrypt(pad(plaintext))

def decode_protobuf(encoded_data: bytes, message_type: message.Message) -> message.Message:
    instance = message_type()
    instance.ParseFromString(encoded_data)
    return instance

async def json_to_proto(json_data: str, proto_message: Message) -> bytes:
    json_format.ParseDict(json.loads(json_data), proto_message)
    return proto_message.SerializeToString()

# === JWT Token Generation ===

async def get_jwt_token(region: str) -> dict:
    """Get JWT token using the new endpoint"""
    creds = REGION_CREDENTIALS.get(region.upper(), REGION_CREDENTIALS["IND"])
    url = f"https://papajwt.vercel.app/kirito?uid={creds['uid']}&password={creds['password']}"
    
    async with httpx.AsyncClient() as client:
        resp = await client.get(url)
        data = resp.json()
        
        if data.get("success"):
            return {
                'jwt': data['jwt'],
                'lock_region': data['region'],
                'url': data['url'],
                'expires_at': data['timestamp'] + 25200  # 7 hours expiry
            }
        else:
            raise Exception(f"Failed to get JWT: {data}")

async def create_jwt(region: str):
    """Create and cache JWT for a region"""
    try:
        token_data = await get_jwt_token(region)
        cached_tokens[region] = {
            'token': token_data['jwt'],
            'region': token_data['lock_region'],
            'server_url': token_data['url'],
            'expires_at': token_data['expires_at']
        }
    except Exception as e:
        print(f"Error creating JWT for {region}: {e}")
        # Fallback to previous token if available
        if region not in cached_tokens:
            raise

async def initialize_tokens():
    """Initialize tokens for all regions"""
    tasks = [create_jwt(r) for r in SUPPORTED_REGIONS]
    await asyncio.gather(*tasks)

async def refresh_tokens_periodically():
    """Refresh tokens periodically"""
    while True:
        await asyncio.sleep(25200)  # 7 hours
        await initialize_tokens()

async def get_token_info(region: str) -> Tuple[str, str, str]:
    """Get token info for a region"""
    info = cached_tokens.get(region)
    if info and time.time() < info['expires_at']:
        return info['token'], info['region'], info['server_url']
    
    await create_jwt(region)
    info = cached_tokens[region]
    return info['token'], info['region'], info['server_url']

async def GetAccountInformation(uid, unk, region, endpoint):
    """Get account information using JWT"""
    payload = await json_to_proto(json.dumps({'a': uid, 'b': unk}), main_pb2.GetPlayerPersonalShow())
    data_enc = aes_cbc_encrypt(MAIN_KEY, MAIN_IV, payload)
    token, lock, server = await get_token_info(region)
    
    headers = {
        'User-Agent': USERAGENT,
        'Connection': "Keep-Alive",
        'Accept-Encoding': "gzip",
        'Content-Type': "application/octet-stream",
        'Expect': "100-continue",
        'Authorization': token,
        'X-Unity-Version': "2018.4.11f1",
        'X-GA': "v1 1",
        'ReleaseVersion': RELEASEVERSION
    }
    
    async with httpx.AsyncClient() as client:
        resp = await client.post(server + endpoint, data=data_enc, headers=headers)
        return json.loads(json_format.MessageToJson(decode_protobuf(resp.content, AccountPersonalShow_pb2.AccountPersonalShowInfo)))

# === Caching Decorator ===

def cached_endpoint(ttl=300):
    def decorator(fn):
        @wraps(fn)
        def wrapper(*a, **k):
            key = (request.path, tuple(request.args.items()))
            if key in cache:
                return cache[key]
            res = fn(*a, **k)
            cache[key] = res
            return res
        return wrapper
    return decorator

# === Flask Routes ===

@app.route('/player-info')
@cached_endpoint()
def get_account_info():
    uid = request.args.get('uid')
    if not uid:
        return jsonify({"error": "Please provide UID."}), 400

    # Check cached region for UID
    if uid in uid_region_cache:
        try:
            return_data = asyncio.run(GetAccountInformation(uid, "7", uid_region_cache[uid], "/GetPlayerPersonalShow"))
            formatted_json = json.dumps(return_data, indent=2, ensure_ascii=False)
            return formatted_json, 200, {'Content-Type': 'application/json; charset=utf-8'}
        except:
            pass  # fallback to testing all regions

    for region in SUPPORTED_REGIONS:
        try:
            return_data = asyncio.run(GetAccountInformation(uid, "7", region, "/GetPlayerPersonalShow"))
            uid_region_cache[uid] = region
            formatted_json = json.dumps(return_data, indent=2, ensure_ascii=False)
            return formatted_json, 200, {'Content-Type': 'application/json; charset=utf-8'}
        except Exception as e:
            print(f"Error with region {region}: {e}")
            continue

    return jsonify({"error": "UID not found in any region."}), 404

@app.route('/refresh', methods=['GET', 'POST'])
def refresh_tokens_endpoint():
    try:
        asyncio.run(initialize_tokens())
        return jsonify({'message': 'Tokens refreshed for all regions.', 'regions': list(cached_tokens.keys())}), 200
    except Exception as e:
        return jsonify({'error': f'Refresh failed: {e}'}), 500

@app.route('/token-status')
def token_status():
    """Check token status for all regions"""
    status = {}
    for region in SUPPORTED_REGIONS:
        info = cached_tokens.get(region)
        if info:
            status[region] = {
                'has_token': bool(info.get('token')),
                'expires_at': info.get('expires_at'),
                'server_url': info.get('server_url'),
                'is_valid': time.time() < info.get('expires_at', 0)
            }
        else:
            status[region] = {'has_token': False}
    return jsonify(status)

@app.route('/health')
def health_check():
    """Health check endpoint"""
    return jsonify({
        'status': 'running',
        'release_version': RELEASEVERSION,
        'supported_regions': list(SUPPORTED_REGIONS),
        'cached_regions': list(cached_tokens.keys())
    })

# === Startup ===

async def startup():
    print(f"Starting with Release Version: {RELEASEVERSION}")
    print(f"Supported Regions: {SUPPORTED_REGIONS}")
    await initialize_tokens()
    print("Tokens initialized successfully!")
    asyncio.create_task(refresh_tokens_periodically())

if __name__ == '__main__':
    asyncio.run(startup())
    app.run(host='0.0.0.0', port=5000, debug=True)
