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
RELEASEVERSION = "OB54"  # UPDATED to OB54
USERAGENT = "Dalvik/2.1.0 (Linux; U; Android 13; CPH2095 Build/RKQ1.211119.001)"
SUPPORTED_REGIONS = {"IND", "BR", "US", "SAC", "NA", "SG", "RU", "ID", "TW", "VN", "TH", "ME", "PK", "CIS", "BD", "EUROPE"}

# === JWT API Configuration ===
JWT_API_URL = "https://papajwt.vercel.app/kirito"
JWT_ACCOUNTS = {
    "IND": {"uid": "4797885396", "password": "M4X_BY_SEMY_km11H3EV"},
    "BR": {"uid": "4044223479", "password": "EB067625F1E2CB705C7561747A46D502480DC5D41497F4C90F3FDBC73B8082ED"},
    "US": {"uid": "4044223479", "password": "EB067625F1E2CB705C7561747A46D502480DC5D41497F4C90F3FDBC73B8082ED"},
    "SAC": {"uid": "4044223479", "password": "EB067625F1E2CB705C7561747A46D502480DC5D41497F4C90F3FDBC73B8082ED"},
    "NA": {"uid": "4044223479", "password": "EB067625F1E2CB705C7561747A46D502480DC5D41497F4C90F3FDBC73B8082ED"},
    "default": {"uid": "4108414251", "password": "E4F9C33BBEB23C0DA0AD7E60F63C8A05D6A878798E3CD32C4E2314C1EEFD4F72"}
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

# === NEW: Get JWT from papajwt API ===

async def get_jwt_from_api(uid: str, password: str) -> dict:
    """Fetch JWT from papajwt API"""
    url = f"{JWT_API_URL}?uid={uid}&password={password}"
    async with httpx.AsyncClient(timeout=30.0) as client:
        resp = await client.get(url)
        data = resp.json()
        if data.get("success"):
            return {
                "jwt": data.get("jwt"),
                "account_uid": data.get("account_uid"),
                "region": data.get("region"),
                "url": data.get("url"),
                "timestamp": data.get("timestamp")
            }
        else:
            raise Exception("JWT API returned error")

# === NEW: Login using JWT (instead of old method) ===

async def login_with_jwt(jwt: str, region: str):
    """Login using JWT token"""
    # JWT ko Base64 decode karke payload nikalte hain
    import jwt as pyjwt
    decoded = pyjwt.decode(jwt, options={"verify_signature": False})
    
    # Login request body prepare karo
    body = json.dumps({
        "open_id": decoded.get("external_id"),
        "open_id_type": "4",
        "login_token": jwt,  # JWT as login token
        "orign_platform_type": "4"
    })
    
    proto_bytes = await json_to_proto(body, FreeFire_pb2.LoginReq())
    payload = aes_cbc_encrypt(MAIN_KEY, MAIN_IV, proto_bytes)
    
    url = "https://loginbp.ggpolarbear.com/MajorLogin"
    headers = {
        'User-Agent': USERAGENT,
        'Connection': "Keep-Alive",
        'Accept-Encoding': "gzip",
        'Content-Type': "application/octet-stream",
        'Expect': "100-continue",
        'X-Unity-Version': "2018.4.11f1",
        'X-GA': "v1 1",
        'ReleaseVersion': RELEASEVERSION
    }
    
    async with httpx.AsyncClient() as client:
        resp = await client.post(url, data=payload, headers=headers)
        msg = json.loads(json_format.MessageToJson(decode_protobuf(resp.content, FreeFire_pb2.LoginRes)))
        
        cached_tokens[region] = {
            'token': f"Bearer {msg.get('token','0')}",
            'region': msg.get('lockRegion','0'),
            'server_url': msg.get('serverUrl','0'),
            'expires_at': time.time() + 25200,
            'jwt': jwt,
            'account_uid': decoded.get("account_id")
        }
        return cached_tokens[region]

# === Updated Token Generation using JWT ===

async def create_jwt_token(region: str):
    """Create token using JWT API"""
    r = region.upper()
    
    # Get credentials for region
    if r in JWT_ACCOUNTS:
        creds = JWT_ACCOUNTS[r]
    else:
        creds = JWT_ACCOUNTS["default"]
    
    # Get JWT from API
    jwt_data = await get_jwt_from_api(creds["uid"], creds["password"])
    
    # Login using JWT
    await login_with_jwt(jwt_data["jwt"], region)
    
    return jwt_data

async def initialize_tokens():
    """Initialize tokens for all regions using JWT"""
    tasks = [create_jwt_token(r) for r in SUPPORTED_REGIONS]
    await asyncio.gather(*tasks)

async def refresh_tokens_periodically():
    while True:
        await asyncio.sleep(25200)  # 7 hours
        await initialize_tokens()

async def get_token_info(region: str) -> Tuple[str,str,str]:
    info = cached_tokens.get(region)
    if info and time.time() < info['expires_at']:
        return info['token'], info['region'], info['server_url']
    
    # Token expired, refresh using JWT
    await create_jwt_token(region)
    info = cached_tokens[region]
    return info['token'], info['region'], info['server_url']

# === Updated GetAccountInformation ===

async def GetAccountInformation(uid, unk, region, endpoint):
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
            pass

    # Try all regions
    for region in SUPPORTED_REGIONS:
        try:
            return_data = asyncio.run(GetAccountInformation(uid, "7", region, "/GetPlayerPersonalShow"))
            uid_region_cache[uid] = region
            formatted_json = json.dumps(return_data, indent=2, ensure_ascii=False)
            return formatted_json, 200, {'Content-Type': 'application/json; charset=utf-8'}
        except Exception as e:
            print(f"Error in region {region}: {e}")
            continue

    return jsonify({"error": "UID not found in any region."}), 404

@app.route('/refresh', methods=['GET','POST'])
def refresh_tokens_endpoint():
    try:
        asyncio.run(initialize_tokens())
        return jsonify({
            'message': 'Tokens refreshed for all regions using JWT API.',
            'regions': list(cached_tokens.keys())
        }), 200
    except Exception as e:
        return jsonify({'error': f'Refresh failed: {e}'}), 500

@app.route('/jwt-info', methods=['GET'])
def get_jwt_info():
    """Get current JWT info for a region"""
    region = request.args.get('region', 'IND').upper()
    if region in cached_tokens:
        info = cached_tokens[region]
        return jsonify({
            'region': region,
            'has_jwt': 'jwt' in info,
            'account_uid': info.get('account_uid'),
            'expires_at': info.get('expires_at'),
            'token_preview': info.get('token', '')[:50] + '...'
        })
    return jsonify({'error': 'Region not found'}), 404

# === Startup ===

async def startup():
    print("🚀 Initializing tokens using JWT API...")
    await initialize_tokens()
    print("✅ Tokens initialized!")
    asyncio.create_task(refresh_tokens_periodically())

if __name__ == '__main__':
    asyncio.run(startup())
    app.run(host='0.0.0.0', port=5000, debug=True)
