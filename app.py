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
import logging

# === Logging Setup ===
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# === Settings ===

MAIN_KEY = base64.b64decode('WWcmdGMlREV1aDYlWmNeOA==')
MAIN_IV = base64.b64decode('Nm95WkRyMjJFM3ljaGpNJQ==')
RELEASEVERSION = "OB54"  # Updated from OB53
GAME_VERSION = "1.126.1"  # New version constant
USERAGENT = "Dalvik/2.1.0 (Linux; U; Android 13; CPH2095 Build/RKQ1.211119.001)"
SUPPORTED_REGIONS = {"IND", "BR", "US", "SAC", "NA", "SG", "RU", "ID", "TW", "VN", "TH", "ME", "PK", "CIS", "BD", "EUROPE"}

# === Device Information for OB54 (for headers and other requests) ===
DEVICE_INFO = {
    "brand": "Handheld",
    "model": "OnePlus A5010",
    "manufacturer": "OnePlus",
    "android_version": "13",
    "api_level": "28",
    "cpu_abi": "armeabi-v7a",
    "screen_density": "480dpi",
    "screen_resolution": "2400x1080",
    "graphics": "OpenGL ES 3.2",
    "gpu": "Adreno (TM) 640",
    "device_id": "4306245793de86da425a52caadf21eed"
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

def get_account_credentials(region: str) -> str:
    r = region.upper()
    if r == "IND":
        return "uid=5163888594&password=E0C602A732D4DD8A81F6C03D800ACA8FC5926E94F5FB0107E5608F5F5DDE259C"
    elif r in {"BR", "US", "SAC", "NA"}:
        return "uid=4044223479&password=EB067625F1E2CB705C7561747A46D502480DC5D41497F4C90F3FDBC73B8082ED"
    else:
        return "uid=4108414251&password=E4F9C33BBEB23C0DA0AD7E60F63C8A05D6A878798E3CD32C4E2314C1EEFD4F72"

# === Token Generation ===

async def get_access_token(account: str):
    url = "https://ffmconnect.live.gop.garenanow.com/oauth/guest/token/grant"
    payload = account + "&response_type=token&client_type=2&client_secret=2ee44819e9b4598845141067b281621874d0d5d7af9d8f7e00c1e54715b7d1e3&client_id=100067"
    headers = {
        'User-Agent': USERAGENT,
        'Connection': "Keep-Alive",
        'Accept-Encoding': "gzip",
        'Content-Type': "application/x-www-form-urlencoded"
    }
    async with httpx.AsyncClient() as client:
        try:
            resp = await client.post(url, data=payload, headers=headers)
            data = resp.json()
            return data.get("access_token", "0"), data.get("open_id", "0")
        except Exception as e:
            logger.error(f"Failed to get access token: {e}")
            return "0", "0"

async def create_jwt(region: str):
    try:
        account = get_account_credentials(region)
        token_val, open_id = await get_access_token(account)
        
        # Only include fields that exist in LoginReq protobuf
        login_data = {
            "openId": open_id,  # Note: field name is openId not open_id
            "openIdType": "4",  # Note: field name is openIdType
            "loginToken": token_val,  # Note: field name is loginToken
            "orignPlatformType": "4"  # Note: field name is orignPlatformType
        }
        
        body = json.dumps(login_data)
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
            'ReleaseVersion': RELEASEVERSION,
            # Additional device info can be sent in headers if needed
            'X-Device-ID': DEVICE_INFO["device_id"],
            'X-Device-Model': DEVICE_INFO["model"],
            'X-Android-Version': DEVICE_INFO["android_version"]
        }
        
        async with httpx.AsyncClient() as client:
            resp = await client.post(url, data=payload, headers=headers)
            
            # Check if response is valid
            if resp.status_code != 200:
                logger.error(f"Failed to create JWT for region {region}: Status {resp.status_code}")
                return
            
            msg = json.loads(json_format.MessageToJson(decode_protobuf(resp.content, FreeFire_pb2.LoginRes)))
            cached_tokens[region] = {
                'token': f"Bearer {msg.get('token','0')}",
                'region': msg.get('lockRegion','0'),
                'server_url': msg.get('serverUrl','0'),
                'expires_at': time.time() + 25200
            }
            logger.info(f"Successfully created JWT for region {region}")
            
    except Exception as e:
        logger.error(f"Error creating JWT for region {region}: {e}")

async def initialize_tokens():
    """Initialize tokens for all regions"""
    logger.info("Initializing tokens for all regions...")
    tasks = [create_jwt(r) for r in SUPPORTED_REGIONS]
    await asyncio.gather(*tasks)
    logger.info("Token initialization complete")

async def refresh_tokens_periodically():
    """Background task to refresh tokens periodically"""
    while True:
        await asyncio.sleep(25200)  # 7 hours
        logger.info("Refreshing tokens periodically...")
        await initialize_tokens()

async def get_token_info(region: str) -> Tuple[str, str, str]:
    """Get token info for a region, refreshing if expired"""
    info = cached_tokens.get(region)
    if info and time.time() < info['expires_at']:
        return info['token'], info['region'], info['server_url']
    
    logger.info(f"Token expired or missing for region {region}, refreshing...")
    await create_jwt(region)
    info = cached_tokens[region]
    return info['token'], info['region'], info['server_url']

async def GetAccountInformation(uid, unk, region, endpoint):
    """Fetch account information from Free Fire API"""
    try:
        # Only include fields that exist in GetPlayerPersonalShow protobuf
        payload_data = {'a': uid, 'b': unk}
        payload = await json_to_proto(json.dumps(payload_data), main_pb2.GetPlayerPersonalShow())
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
            'ReleaseVersion': RELEASEVERSION,
            # Add device info in headers
            'X-Device-ID': DEVICE_INFO["device_id"],
            'X-Device-Model': DEVICE_INFO["model"]
        }
        
        async with httpx.AsyncClient() as client:
            resp = await client.post(server + endpoint, data=data_enc, headers=headers)
            
            if resp.status_code != 200:
                raise Exception(f"API returned status {resp.status_code}")
            
            return json.loads(json_format.MessageToJson(
                decode_protobuf(resp.content, AccountPersonalShow_pb2.AccountPersonalShowInfo)
            ))
            
    except Exception as e:
        logger.error(f"Error fetching account info for UID {uid} in region {region}: {e}")
        raise

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

@app.route('/')
def index():
    """Welcome endpoint"""
    return jsonify({
        "service": "Free Fire API",
        "version": RELEASEVERSION,
        "game_version": GAME_VERSION,
        "status": "running",
        "supported_regions": list(SUPPORTED_REGIONS),
        "endpoints": {
            "/player-info": "Get player information by UID",
            "/refresh": "Refresh tokens for all regions",
            "/test-ob54": "Test OB54 compatibility",
            "/regions": "List all supported regions",
            "/stats": "Get API statistics",
            "/device-info": "Get device information"
        }
    })

@app.route('/player-info')
@cached_endpoint()
def get_account_info():
    """Get player information by UID"""
    uid = request.args.get('uid')
    if not uid:
        return jsonify({"error": "Please provide UID."}), 400

    # Check cached region for UID
    if uid in uid_region_cache:
        try:
            return_data = asyncio.run(GetAccountInformation(
                uid, "7", uid_region_cache[uid], "/GetPlayerPersonalShow"
            ))
            formatted_json = json.dumps(return_data, indent=2, ensure_ascii=False)
            return formatted_json, 200, {'Content-Type': 'application/json; charset=utf-8'}
        except Exception as e:
            logger.warning(f"Failed with cached region for UID {uid}: {e}")
            # Fall through to try all regions

    # Try all regions
    for region in SUPPORTED_REGIONS:
        try:
            return_data = asyncio.run(GetAccountInformation(
                uid, "7", region, "/GetPlayerPersonalShow"
            ))
            uid_region_cache[uid] = region
            formatted_json = json.dumps(return_data, indent=2, ensure_ascii=False)
            return formatted_json, 200, {'Content-Type': 'application/json; charset=utf-8'}
        except Exception as e:
            logger.debug(f"UID {uid} not found in region {region}: {e}")
            continue

    return jsonify({"error": "UID not found in any region."}), 404

@app.route('/refresh', methods=['GET', 'POST'])
def refresh_tokens_endpoint():
    """Manually refresh tokens for all regions"""
    try:
        asyncio.run(initialize_tokens())
        return jsonify({
            'message': 'Tokens refreshed successfully for all regions.',
            'version': RELEASEVERSION,
            'game_version': GAME_VERSION
        }), 200
    except Exception as e:
        logger.error(f"Token refresh failed: {e}")
        return jsonify({'error': f'Refresh failed: {e}'}), 500

@app.route('/test-ob54', methods=['GET'])
def test_ob54_compatibility():
    """Test endpoint with OB54 payload structure"""
    try:
        # Test with the correct field names for LoginReq
        test_payload = {
            "openId": DEVICE_INFO["device_id"],
            "openIdType": "4",
            "loginToken": "c69ae208fad72738b674b2847b50a3a1dfa25d1a19fae745fc76ac4a0e414c94",
            "orignPlatformType": "4"
        }
        
        # Test proto conversion
        proto_bytes = asyncio.run(json_to_proto(
            json.dumps(test_payload),
            FreeFire_pb2.LoginReq()
        ))
        
        return jsonify({
            "status": "OB54 compatible",
            "version": RELEASEVERSION,
            "game_version": GAME_VERSION,
            "test_payload": test_payload,
            "proto_size": len(proto_bytes),
            "device_info": DEVICE_INFO,
            "message": "Successfully tested OB54 payload structure"
        }), 200
    except Exception as e:
        logger.error(f"OB54 test failed: {e}")
        return jsonify({"error": str(e)}), 500

@app.route('/device-info', methods=['GET'])
def get_device_info():
    """Get current device information used for requests"""
    return jsonify({
        "device_info": DEVICE_INFO,
        "version": RELEASEVERSION,
        "game_version": GAME_VERSION
    })

@app.route('/regions', methods=['GET'])
def get_regions():
    """List all supported regions with their token status"""
    region_status = {}
    for region in SUPPORTED_REGIONS:
        info = cached_tokens.get(region)
        if info:
            region_status[region] = {
                "has_token": True,
                "expires_at": info.get('expires_at'),
                "is_valid": time.time() < info.get('expires_at', 0),
                "region": info.get('region'),
                "server_url": info.get('server_url')
            }
        else:
            region_status[region] = {
                "has_token": False,
                "expires_at": None,
                "is_valid": False
            }
    
    return jsonify({
        "total_regions": len(SUPPORTED_REGIONS),
        "regions": region_status,
        "version": RELEASEVERSION,
        "game_version": GAME_VERSION
    })

@app.route('/stats', methods=['GET'])
def get_stats():
    """Get API statistics"""
    return jsonify({
        "cache_size": len(cache),
        "cache_maxsize": cache.maxsize,
        "cached_regions": len(cached_tokens),
        "uid_region_cache_size": len(uid_region_cache),
        "version": RELEASEVERSION,
        "game_version": GAME_VERSION,
        "supported_regions": len(SUPPORTED_REGIONS),
        "device_id": DEVICE_INFO["device_id"]
    })

@app.route('/clear-cache', methods=['POST'])
def clear_cache():
    """Clear the cache"""
    cache.clear()
    return jsonify({"message": "Cache cleared successfully"}), 200

@app.errorhandler(404)
def not_found(error):
    return jsonify({"error": "Endpoint not found"}), 404

@app.errorhandler(500)
def internal_error(error):
    return jsonify({"error": "Internal server error"}), 500

# === Startup ===

async def startup():
    """Initialize the application"""
    logger.info(f"Starting Free Fire API with {RELEASEVERSION} ({GAME_VERSION})")
    logger.info(f"Device ID: {DEVICE_INFO['device_id']}")
    await initialize_tokens()
    asyncio.create_task(refresh_tokens_periodically())
    logger.info("API ready to accept requests")

async def shutdown():
    """Clean shutdown"""
    logger.info("Shutting down API...")
    # Add any cleanup code here

if __name__ == '__main__':
    try:
        asyncio.run(startup())
        app.run(host='0.0.0.0', port=5000, debug=False)  # Set debug=False for production
    except KeyboardInterrupt:
        asyncio.run(shutdown())
        logger.info("API stopped")
    except Exception as e:
        logger.error(f"Fatal error: {e}")
        raise
