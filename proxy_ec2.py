import asyncio
import json
import base64
import secrets
import redis.asyncio as redis
import logging
from fastapi import FastAPI, Request, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.concurrency import asynccontextmanager
from web3 import AsyncWeb3, Web3
from siwe import SiweMessage
from umbral_pre import Capsule, KeyFrag, reencrypt, PublicKey
import os
import urllib.request
from dotenv import load_dotenv

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[logging.StreamHandler()],
)
logger = logging.getLogger(__name__)

load_dotenv(".env.local")

# Load ABI
try:
    with open("abi.json", "r") as f:
        CONTRACT_ABI = json.load(f)
except Exception as e:
    logger.warning(f"Could not load abi.json: {e}")
    CONTRACT_ABI = []

RPC_URL = os.getenv("RPC_URL", "http://127.0.0.1:8545")
CONTRACT_ADDRESS = os.getenv("CONTRACT_ADDRESS", "")
REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379")
RK_TTL_SECONDS = 3600
ENCLAVE_CID = 16  # CID for VSOCK connection to enclave
ENCLAVE_PORT = 12345
ENCLAVE_STORAGE_DIR = "enclave_storage"

os.makedirs(ENCLAVE_STORAGE_DIR, exist_ok=True)

redis_pool = None
w3_client = None


def save_enclave_state(encrypted_master_key: str | None, encrypted_state: str | None):
    """Save encrypted state to disk."""
    try:
        if encrypted_master_key:
            with open(
                os.path.join(ENCLAVE_STORAGE_DIR, "encrypted_master_key.bin"), "w"
            ) as f:
                f.write(encrypted_master_key)

        if encrypted_state:
            with open(
                os.path.join(ENCLAVE_STORAGE_DIR, "encrypted_state.bin"), "w"
            ) as f:
                f.write(encrypted_state)

        if encrypted_master_key or encrypted_state:
            logger.info("[EC2] Enclave state saved to disk")
    except Exception as e:
        logger.error(f"[EC2] Failed to save enclave state: {e}")


def load_enclave_state() -> tuple[str | None, str | None]:
    """Load encrypted state from disk."""
    mk = None
    state = None
    try:
        mk_path = os.path.join(ENCLAVE_STORAGE_DIR, "encrypted_master_key.bin")
        state_path = os.path.join(ENCLAVE_STORAGE_DIR, "encrypted_state.bin")

        if os.path.exists(mk_path):
            with open(mk_path, "r") as f:
                mk = f.read().strip()

        if os.path.exists(state_path):
            with open(state_path, "r") as f:
                state = f.read().strip()

        return mk, state
    except Exception as e:
        logger.error(f"[EC2] Failed to load enclave state: {e}")
        return None, None


def process_enclave_response(response_bytes: bytes | None) -> dict | None:
    """
    Parse enclave response, handle state persistence, and return data dict.
    Returns None on error.
    """
    if not response_bytes:
        return None

    try:
        data = json.loads(response_bytes.decode("utf-8"))
        if not isinstance(data, dict):
            logger.error("Invalid response format")
            return None

        # Check for state update
        new_state = data.get("new_encrypted_state")
        master_key = data.get("encrypted_master_key")  # from init
        initial_state = data.get("encrypted_state")  # from init

        if new_state:
            save_enclave_state(None, new_state)
        elif master_key and initial_state:
            save_enclave_state(master_key, initial_state)

        # Surface state persistence warnings from enclave
        state_warning = data.get("state_warning")
        if state_warning:
            logger.error(
                f"[EC2] CRITICAL: Enclave state persistence failed: {state_warning}"
            )

        if data.get("status") == "error":
            logger.error(f"Enclave Error: {data.get('message')}")
            return data

        return data
    except Exception as e:
        logger.error(f"Failed to process enclave response: {e}")
        return None


async def forward_enclave(payload: bytes) -> bytes | None:
    """Forward payload to enclave via VSOCK (or TCP in local mode)."""
    import os

    is_local = os.getenv("IS_LOCAL_ENV", "False").lower() == "true"

    try:
        if is_local:
            # Local mode: use TCP
            reader, writer = await asyncio.open_connection("127.0.0.1", ENCLAVE_PORT)
        else:
            # AWS server mode: use VSOCK
            import socket

            if not hasattr(socket, "AF_VSOCK"):
                raise RuntimeError("AF_VSOCK not available")

            sock = socket.socket(socket.AF_VSOCK, socket.SOCK_STREAM)  # type: ignore
            sock.setblocking(False)

            loop = asyncio.get_event_loop()
            await loop.sock_connect(sock, (ENCLAVE_CID, ENCLAVE_PORT))

            reader, writer = await asyncio.open_connection(sock=sock)

        # Send length-prefixed message for proper framing
        logger.info(f"[EC2] Forwarding {len(payload)} bytes to enclave")
        length_prefix = len(payload).to_bytes(4, "big")
        writer.write(length_prefix + payload)
        await writer.drain()

        # Read response length first
        length_bytes = await reader.readexactly(4)
        response_length = int.from_bytes(length_bytes, "big")

        # Read the full response
        data = await reader.readexactly(response_length)
        logger.info(f"[EC2] Received {len(data)} bytes from enclave")

        writer.close()
        await writer.wait_closed()
        return data

    except asyncio.IncompleteReadError as e:
        logger.error(f"Incomplete read from enclave: {e}")
        return None
    except Exception as e:
        logger.error(f"Connection error: {e}")
        return None


def fetch_iam_credentials() -> dict | None:
    """Fetch temporary IAM role credentials from EC2 instance metadata (IMDSv2)."""
    try:
        # Step 1: Get IMDSv2 token
        token_req = urllib.request.Request(
            "http://169.254.169.254/latest/api/token",
            method="PUT",
            headers={"X-aws-ec2-metadata-token-ttl-seconds": "21600"},
        )
        with urllib.request.urlopen(token_req, timeout=3) as resp:
            token = resp.read().decode()

        headers = {"X-aws-ec2-metadata-token": token}

        # Step 2: Get the role name
        role_req = urllib.request.Request(
            "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
            headers=headers,
        )
        with urllib.request.urlopen(role_req, timeout=3) as resp:
            role_name = resp.read().decode().strip()

        # Step 3: Get the credentials
        creds_req = urllib.request.Request(
            f"http://169.254.169.254/latest/meta-data/iam/security-credentials/{role_name}",
            headers=headers,
        )
        with urllib.request.urlopen(creds_req, timeout=3) as resp:
            creds = json.loads(resp.read().decode())

        logger.info(f"[EC2] Fetched IAM credentials for role: {role_name}")
        return {
            "aws_access_key_id": creds["AccessKeyId"],
            "aws_secret_access_key": creds["SecretAccessKey"],
            "aws_session_token": creds["Token"],
        }
    except Exception as e:
        logger.error(f"[EC2] Failed to fetch IAM credentials: {e}")
        return None


async def init_enclave():
    """Initialize enclave with stored state."""
    mk, state = load_enclave_state()

    action = "init"
    payload_dict = {"action": action}

    # Fetch IAM credentials and forward to enclave
    creds = fetch_iam_credentials()
    if creds:
        payload_dict["credentials"] = creds
    else:
        logger.warning("[EC2] No IAM credentials available for enclave init")

    if mk and state:
        logger.info("[EC2] Found persisted state, restoring enclave...")
        payload_dict["encrypted_master_key"] = mk
        payload_dict["encrypted_state"] = state
    else:
        logger.info("[EC2] No persisted state, initializing new enclave...")
        kms_key = os.getenv("KMS_KEY_ID")
        if kms_key:
            payload_dict["kms_key_id"] = kms_key

    response = await forward_enclave(json.dumps(payload_dict).encode())
    res_data = process_enclave_response(response)

    if res_data and res_data.get("status") == "success":
        logger.info("[EC2] Enclave initialized successfully")
    else:
        logger.error("[EC2] Enclave initialization failed")


async def get_web3():
    """Get a Web3 instance with appropriate provider."""
    global w3_client
    if w3_client is None:
        if RPC_URL.startswith("http"):
            w3_client = AsyncWeb3(AsyncWeb3.AsyncHTTPProvider(RPC_URL))
        else:
            w3_client = AsyncWeb3(AsyncWeb3.WebSocketProvider(RPC_URL))
    return w3_client


async def get_contract():
    w3 = await get_web3()
    contract = w3.eth.contract(
        address=(
            Web3.to_checksum_address(CONTRACT_ADDRESS) if CONTRACT_ADDRESS else None
        ),
        abi=CONTRACT_ABI,
    )
    return contract, w3


async def get_redis():
    """Get Redis connection from pool."""
    global redis_pool
    if redis_pool is None:
        redis_pool = await redis.from_url(REDIS_URL)
    return redis_pool


async def fetch_file_blockchain(cid: str):
    contract, w3 = await get_contract()
    file = await contract.functions.getFile(cid).call()
    return file


async def get_rk(owner: str, requester: str):
    """Get re-encryption key from cache or enclave (on-demand)."""
    redis = await get_redis()
    logger.info(f"[EC2] Fetching RK for {owner}->{requester}")
    rk_key = f"rk:{owner.lower()}:{requester.lower()}"
    rk = await redis.get(rk_key)
    if rk:
        logger.info(f"[EC2] RK found in cache for {owner}->{requester}")
        return rk

    logger.info(
        f"[EC2] RK not in cache, requesting from enclave for {owner}->{requester}..."
    )
    payload = json.dumps(
        {
            "action": "get_rk",
            "owner": owner,
            "requester": requester,
        }
    ).encode()

    response = await forward_enclave(payload)
    data = process_enclave_response(response)

    if data and data.get("status") == "success":
        rk_hex = data.get("data")
        if rk_hex:
            rk = bytes.fromhex(rk_hex)
            await redis.set(rk_key, rk, ex=RK_TTL_SECONDS)
            return rk
    return None


async def get_public_key(redis, address: str) -> tuple[bytes | None, bytes | None]:
    """Get user's public key and verifying key from cache or enclave.

    Returns:
        Tuple of (public_key_bytes, verifying_key_bytes) or (None, None) on failure
    """
    pk_key = f"pk:{address.lower()}"
    vk_key = f"vk:{address.lower()}"

    pk = await redis.get(pk_key)
    vk = await redis.get(vk_key)

    if pk and vk:
        logger.info(f"[EC2] PK/VK found in cache for {address}")
        return pk, vk
    logger.info(f"[EC2] PK/VK not in cache for {address}, requesting from enclave...")

    payload = json.dumps(
        {
            "action": "get_public_key",
            "address": address,
        }
    ).encode()

    response = await forward_enclave(payload)
    data = process_enclave_response(response)

    if data and data.get("status") == "success":
        pk_hex = data.get("public_key")
        vk_hex = data.get("verifying_key")

        if pk_hex and vk_hex:
            pk = bytes.fromhex(pk_hex)
            vk = bytes.fromhex(vk_hex)
            # Cache both keys (they don't change)
            await redis.set(pk_key, pk, ex=RK_TTL_SECONDS * 24)
            await redis.set(vk_key, vk, ex=RK_TTL_SECONDS * 24)
            logger.info(f"[EC2] PK/VK cached for {address}")
            return pk, vk
    return None, None


async def reencrypt_capsule(
    rk_bytes: bytes,
    capsule_bytes: bytes,
    owner_pk_bytes: bytes,
    owner_vk_bytes: bytes,
    requester_pk_bytes: bytes,
) -> bytes:
    """
    Re-encrypt a capsule using the re-encryption key fragment.

    Args:
        rk_bytes: Serialized KeyFrag from enclave
        capsule_bytes: Serialized Capsule
        owner_pk_bytes: Owner's encryption public key bytes (delegating_pk)
        owner_vk_bytes: Owner's verifying key bytes (for kfrag signature verification)
        requester_pk_bytes: Requester's public key bytes (receiving_pk)

    Returns:
        Serialized CapsuleFrag
    """
    try:
        capsule = Capsule.from_bytes(capsule_bytes)

        owner_pk = PublicKey.from_compressed_bytes(owner_pk_bytes)
        owner_vk = PublicKey.from_compressed_bytes(owner_vk_bytes)
        requester_pk = PublicKey.from_compressed_bytes(requester_pk_bytes)

        kfrag = KeyFrag.from_bytes(rk_bytes)
        verified_kfrag = kfrag.verify(
            verifying_pk=owner_vk, delegating_pk=owner_pk, receiving_pk=requester_pk
        )

        cfrag = reencrypt(capsule=capsule, kfrag=verified_kfrag)

        return bytes(cfrag)

    except Exception as e:
        raise ValueError(f"Re-encryption failed: {str(e)}")


@asynccontextmanager
async def lifespan(_: FastAPI):
    global redis_pool, w3_client
    # Startup
    redis_pool = await redis.from_url(REDIS_URL)

    # Initialize Web3
    logger.info(f"[EC2] Connecting to RPC: {RPC_URL}")
    logger.info(f"[EC2] Using Contract Address: {CONTRACT_ADDRESS}")
    if RPC_URL.startswith("http"):
        w3_client = AsyncWeb3(AsyncWeb3.AsyncHTTPProvider(RPC_URL))
    else:
        w3_client = AsyncWeb3(AsyncWeb3.WebSocketProvider(RPC_URL))

    try:
        if await w3_client.is_connected():
            logger.info(f"Connected to Ethereum node at {RPC_URL}")
        else:
            logger.error(f"Failed to connect to Ethereum node at {RPC_URL}")
    except Exception as e:
        logger.error(f"Error checking Ethereum connection: {e}")

    # Init Enclave
    await init_enclave()

    yield
    # Shutdown
    if redis_pool:
        await redis_pool.close()


app = FastAPI(lifespan=lifespan)

allowed_origins = [
    "http://localhost:5173",
    "http://localhost:3000",
    "http://localhost:5174",
    "http://localhost:5175",
]

# Add origins from env var
env_origins = os.getenv("ALLOWED_ORIGINS")
if env_origins:
    allowed_origins.extend([o.strip() for o in env_origins.split(",")])

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Vite/React dev servers
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

nonce_store: dict[str, float] = {}
NONCE_EXPIRY_SECONDS = 300  # 5 minutes


@app.get("/api/nonce")
async def get_nonce():
    """Generate a nonce for SIWE authentication."""
    import time

    nonce = secrets.token_hex(16)
    nonce_store[nonce] = time.time()
    logger.info(f"[EC2] Nonce issued. Active nonces: {len(nonce_store)}")

    # Clean up expired nonces
    current_time = time.time()
    expired = [
        k for k, v in nonce_store.items() if current_time - v > NONCE_EXPIRY_SECONDS
    ]
    for k in expired:
        del nonce_store[k]
    if expired:
        logger.info(f"[EC2] Cleaned up {len(expired)} expired nonces")

    return {"nonce": nonce}


@app.post("/api/verify")
async def verify_siwe(request: Request):
    """
    Verify SIWE signature and retrieve user's public key from enclave.
    """
    import time

    try:
        body = await request.json()
        message_str = body.get("message")
        signature = body.get("signature")

        if not message_str or not signature:
            return {"status": "error", "message": "Missing message or signature"}

        # Parse and verify SIWE message
        siwe_message = SiweMessage.from_message(message_str)

        # Verify nonce exists and hasn't expired
        nonce = siwe_message.nonce
        if nonce not in nonce_store:
            logger.warning("[EC2] SIWE nonce missing or expired")
            return {"status": "error", "message": "Invalid or expired nonce"}

        if time.time() - nonce_store[nonce] > NONCE_EXPIRY_SECONDS:
            del nonce_store[nonce]
            logger.warning("[EC2] SIWE nonce expired")
            return {"status": "error", "message": "Nonce expired"}

        # Verify signature
        logger.info(f"[EC2] Verifying SIWE for {siwe_message.address}")
        siwe_message.verify(signature)
        logger.info("[EC2] SIWE signature verified")

        # Remove used nonce
        del nonce_store[nonce]

        address = siwe_message.address

        # Forward to enclave for registration/login
        payload = json.dumps(
            {
                "action": "login",
                "address": address,
                "signature": signature,
                "message": message_str,
            }
        ).encode("utf-8")

        response = await forward_enclave(payload)
        data = process_enclave_response(response)  # Use helper

        if data and data.get("status") == "success":
            logger.info("[EC2] Enclave login successful")
            return {
                "status": "success",
                "pk": data.get("public_key") or data.get("data"),
                "verifying_key": data.get("verifying_key"),
                "address": data.get("address"),
            }
        else:
            return {
                "status": "error",
                "message": data.get("message") if data else "Enclave Error",
            }

    except Exception as e:
        logger.error(f"Login failed: {str(e)}")
        return {"status": "error", "message": "Login failed"}


@app.post("/api/decrypt-capsule")
async def decrypt_capsule(request: Request):
    """
    Request enclave to decrypt a capsule.
    Handles blockchain fetch and optional re-encryption if the requester is not the owner.
    """
    try:
        body = await request.json()
        address = body.get("address")
        cid = body.get("cid")
        signature = body.get("signature")
        message = body.get("message")
        ephemeral_public_key = body.get("ephemeral_public_key")

        if not address or not cid:
            return {"status": "error", "message": "Missing address or cid"}

        logger.info(f"[EC2] Decrypt capsule request for {address} on {cid}")

        # 1. Fetch from blockchain
        try:
            logger.info(f"[EC2] Fetching file data from blockchain for {cid}")
            file_data = await fetch_file_blockchain(cid)
            # file_data structure: (owner, cid, capsule, ciphertext, exist) per ABI
            chain_owner = file_data[0]
            capsule = file_data[2]
            ciphertext_bytes = file_data[3]

            ciphertext_hex = ciphertext_bytes.hex()

            # Convert capsule bytes to hex
            if isinstance(capsule, str):
                capsule_bytes = bytes.fromhex(capsule.replace("0x", ""))
            elif isinstance(capsule, bytes):
                capsule_bytes = capsule
            else:
                capsule_bytes = bytes(capsule)

            capsule_hex = capsule_bytes.hex()

            logger.info(
                f"[EC2] Chain owner: {chain_owner}, Ciphertext length: {len(ciphertext_hex)}"
            )
        except Exception as e:
            logger.error(f"[EC2] Failed to fetch data from chain: {e}")
            return {
                "status": "error",
                "message": "Failed to fetch file data from blockchain",
            }

        if not ciphertext_hex:
            return {"status": "error", "message": "Ciphertext not found on-chain"}

        redis_client = await get_redis()
        is_reencrypted = False
        cfrag_hex = ""

        # 2. Check if requester wants someone else's file
        if address.lower() != chain_owner.lower():
            logger.info(
                f"[EC2] Requester {address} is not the owner. Checking access and re-encrypting..."
            )
            # Verify on-chain access status
            try:
                contract, w3 = await get_contract()
                status = await contract.functions.getAccessStatus(cid, address).call()
                # AccessStatus enum: 0=NONE, 1=PENDING, 2=APPROVED, 3=DENIED, 4=REVOKED
                if status != 2:
                    logger.warning(f"[EC2] Access not approved for {address} on {cid}")
                    return {
                        "status": "error",
                        "message": "Access not approved on-chain",
                    }
            except Exception as e:
                logger.error(f"Access verification failed: {e}")
                return {"status": "error", "message": "Access verification failed"}

            # Get re-encryption key (RK) on-demand
            rk = await get_rk(chain_owner, address)
            if not rk:
                return {
                    "status": "error",
                    "message": "could not obtain re-encryption key",
                }
            logger.info(f"[EC2] RK retrieved for {chain_owner}->{address}")

            owner_pk_bytes, owner_vk_bytes = await get_public_key(redis_client, chain_owner)
            requester_pk_bytes, _ = await get_public_key(redis_client, address)

            if not owner_pk_bytes or not owner_vk_bytes:
                return {"status": "error", "message": "owner not registered in enclave"}
            if not requester_pk_bytes:
                return {
                    "status": "error",
                    "message": "requester not registered in enclave",
                }

            # Perform re-encryption
            try:
                logger.info("[EC2] Re-encrypting capsule locally...")
                reenc_capsule = await reencrypt_capsule(
                    rk_bytes=rk,
                    capsule_bytes=capsule_bytes,
                    owner_pk_bytes=owner_pk_bytes,
                    owner_vk_bytes=owner_vk_bytes,
                    requester_pk_bytes=requester_pk_bytes,
                )
                cfrag_hex = reenc_capsule.hex()
                is_reencrypted = True
                logger.info("[EC2] Re-encryption successful")
            except Exception as e:
                logger.error(f"Re-encryption failed: {e}")
                return {"status": "error", "message": "Re-encryption failed"}
        else:
            logger.info("[EC2] Requester is the owner. Direct decryption.")

        # 3. Forward to enclave for decryption
        logger.info("[EC2] Forwarding decrypt request to enclave")
        payload = json.dumps(
            {
                "action": "decrypt_capsule",
                "address": address,
                "capsule": capsule_hex,
                "ciphertext": ciphertext_hex,
                "cid": cid,
                "is_reencrypted": is_reencrypted,
                "cfrag": cfrag_hex,
                "owner": chain_owner,
                "signature": signature,
                "message": message,
                "ephemeral_public_key": ephemeral_public_key,
            }
        ).encode()

        response = await forward_enclave(payload)
        data = process_enclave_response(response)  # Use helper

        if data and data.get("status") == "success":
            logger.info("[EC2] Decrypt successful")
            return data
        else:
            return data if data else {"status": "error", "message": "Enclave error"}

    except Exception as e:
        logger.error(f"Decryption failed: {str(e)}")
        return {"status": "error", "message": "Decryption failed"}
