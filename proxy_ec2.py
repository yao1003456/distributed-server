import asyncio
import json
import base64
import secrets
import redis.asyncio as redis
from fastapi import FastAPI, Request, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.concurrency import asynccontextmanager
from web3 import AsyncWeb3, Web3
from siwe import SiweMessage
from socket_utils import get_socket_type, get_connection_address
from umbral import Capsule, KeyFrag, reencrypt, PublicKey
import os
from dotenv import load_dotenv

load_dotenv(".env.local")

with open("abi.json", "r") as f:
    CONTRACT_ABI = json.load(f)
RPC_URL = os.getenv("RPC_URL")
CONTRACT_ADDRESS = os.getenv("CONTRACT_ADDRESS")
REDIS_URL = os.getenv("REDIS_URL")
RK_TTL_SECONDS = 3600
ENCLAVE_CID = 16  # CID for VSOCK connection to enclave (parent VM is typically 3, enclave is assigned)
ENCLAVE_PORT = 12345

# Global Redis connection pool
redis_pool = None


# helper functions for blockchain interaction
async def get_web3():
    """Get an AsyncWeb3 instance with WebSocket provider."""
    from web3.providers import WebSocketProvider

    provider = WebSocketProvider(RPC_URL)
    w3 = AsyncWeb3(provider)
    return w3


async def get_contract():
    w3 = await get_web3()
    contract = w3.eth.contract(
        address=Web3.to_checksum_address(CONTRACT_ADDRESS), abi=CONTRACT_ABI
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


async def get_rk(redis, owner: str, requester: str):
    """Get re-encryption key from cache or enclave."""
    print(f"[EC2] Fetching RK for {owner}->{requester}")
    rk_key = f"rk:{owner.lower()}:{requester.lower()}"
    rk = await redis.get(rk_key)
    if rk:
        print(f"[EC2] RK found in cache")
        return rk

    print(f"[EC2] RK not in cache, requesting from enclave...")
    payload = json.dumps(
        {
            "action": "get_rk",
            "owner": owner,
            "requester": requester,
        }
    ).encode()

    response = await forward_enclave(payload)
    rk = parse_enclave_response(response)

    if rk:
        await redis.set(rk_key, rk, ex=RK_TTL_SECONDS)
    return rk


async def get_public_key(redis, address: str) -> bytes | None:
    """Get user's public key from cache or enclave."""
    pk_key = f"pk:{address.lower()}"
    pk = await redis.get(pk_key)
    if pk:
        return pk

    payload = json.dumps(
        {
            "action": "get_public_key",
            "address": address,
        }
    ).encode()

    response = await forward_enclave(payload)
    pk = parse_enclave_response(response)

    if pk:
        # Cache public keys longer since they don't change
        await redis.set(pk_key, pk, ex=RK_TTL_SECONDS * 24)
    return pk


def parse_enclave_response(response: bytes | None) -> bytes | None:
    """
    Parse enclave response which may be:
    - Raw bytes (for binary data like keys, kfrags)
    - JSON with status and data fields
    - JSON error response
    """
    if response is None:
        return None

    # Try to parse as JSON first
    try:
        data = json.loads(response.decode("utf-8"))
        if isinstance(data, dict):
            if data.get("status") == "error":
                print(f"Enclave error: {data.get('message')}")
                return None
            if "data" in data:
                # Data is hex-encoded
                return bytes.fromhex(data["data"])
        # If JSON but not our expected format, return as-is
        return response
    except (json.JSONDecodeError, UnicodeDecodeError):
        # Not JSON, return raw bytes
        return response


# uses rk to re-encrypt capsule from owner to requester
async def reencrypt_capsule(
    rk_bytes: bytes,
    capsule_bytes: bytes,
    owner_pk_bytes: bytes,
    requester_pk_bytes: bytes,
) -> bytes:
    """
    Re-encrypt a capsule using the re-encryption key fragment.

    Args:
        rk_bytes: Serialized KeyFrag from enclave
        capsule_bytes: Serialized Capsule
        owner_pk_bytes: Owner's public key bytes (for kfrag verification)
        requester_pk_bytes: Requester's public key bytes (for kfrag verification)

    Returns:
        Serialized CapsuleFrag
    """
    try:
        # Deserialize the capsule
        capsule = Capsule.from_bytes(capsule_bytes)

        # Deserialize keys for verification
        owner_pk = PublicKey.from_bytes(owner_pk_bytes)
        requester_pk = PublicKey.from_bytes(requester_pk_bytes)

        # Deserialize and verify the key fragment
        # KeyFrag must be verified before use in reencryption
        kfrag = KeyFrag.from_bytes(rk_bytes)
        verified_kfrag = kfrag.verify(
            verifying_pk=owner_pk, delegating_pk=owner_pk, receiving_pk=requester_pk
        )

        # Perform re-encryption using the module-level function
        cfrag = reencrypt(capsule=capsule, kfrag=verified_kfrag)

        # Return the serialized verified capsule fragment
        return bytes(cfrag)

    except Exception as e:
        raise ValueError(f"Re-encryption failed: {str(e)}")


async def event_listener():
    contract, w3 = await get_contract()
    redis = await get_redis()

    # Get the latest block as starting point
    latest_block = await w3.eth.block_number

    while True:
        try:
            current_block = await w3.eth.block_number

            if current_block > latest_block:
                # Fetch AccessGranted events
                access_granted_events = await contract.events.AccessGranted.get_logs(
                    fromBlock=latest_block + 1, toBlock=current_block
                )

                # Fetch AccessDenied events
                access_denied_events = await contract.events.AccessDenied.get_logs(
                    fromBlock=latest_block + 1, toBlock=current_block
                )

                # Handle AccessGranted events
                for event in access_granted_events:
                    cid = event["args"]["cid"]
                    owner = event["args"]["owner"]
                    requester = event["args"]["requester"]

                    # check redis cache for existing rk
                    rk_key = f"rk:{owner.lower()}:{requester.lower()}"
                    existing_rk = await redis.get(rk_key)

                    if not existing_rk:
                        # ping enclave for rk
                        payload = json.dumps(
                            {
                                "action": "get_rk",
                                "owner": owner,
                                "requester": requester,
                            }
                        ).encode()
                        response = await forward_enclave(payload)
                        rk = parse_enclave_response(response)

                        if rk:
                            # store rk in redis with expiration
                            await redis.set(rk_key, rk, ex=RK_TTL_SECONDS)
                            print(
                                f"Cached RK for owner={owner}, requester={requester}, cid={cid}"
                            )
                        else:
                            print(
                                f"Failed to obtain RK for owner={owner}, requester={requester}"
                            )
                    else:
                        print(
                            f"RK already cached for owner={owner}, requester={requester}"
                        )

                # Handle AccessDenied events
                for event in access_denied_events:
                    owner = event["args"]["owner"]
                    requester = event["args"]["requester"]

                    # remove rk from redis
                    rk_key = f"rk:{owner.lower()}:{requester.lower()}"
                    deleted = await redis.delete(rk_key)

                    if deleted:
                        print(f"Removed RK for owner={owner}, requester={requester}")
                    else:
                        print(
                            f"No RK found to remove for owner={owner}, requester={requester}"
                        )

                latest_block = current_block

        except Exception as e:
            print(f"Event listener error: {e}")

        await asyncio.sleep(5)


# forwards payload to enclave and retrieves response
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
        print(f"[EC2] Forwarding {len(payload)} bytes to enclave")
        length_prefix = len(payload).to_bytes(4, "big")
        writer.write(length_prefix + payload)
        await writer.drain()

        # Read response length first
        length_bytes = await reader.readexactly(4)
        response_length = int.from_bytes(length_bytes, "big")

        # Read the full response
        data = await reader.readexactly(response_length)
        print(f"[EC2] Received {len(data)} bytes from enclave")

        writer.close()
        await writer.wait_closed()
        return data

    except asyncio.IncompleteReadError as e:
        print(f"Incomplete read from enclave: {e}")
        return None
    except Exception as e:
        print(f"Connection error: {e}")
        return None


@asynccontextmanager
async def lifespan(_: FastAPI):
    global redis_pool
    # runs on startup
    redis_pool = await redis.from_url(REDIS_URL)
    task = asyncio.create_task(event_listener())
    yield
    # runs on shutdown
    task.cancel()
    try:
        await task
    except asyncio.CancelledError:
        pass
    # Close Redis pool
    if redis_pool:
        await redis_pool.close()


app = FastAPI(lifespan=lifespan)

# CORS middleware for browser requests
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",
        "http://localhost:3000",
    ],  # Vite/React dev servers
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# TODO: use Redis in production
# In-memory nonce store (use Redis in production)
nonce_store: dict[str, float] = {}
NONCE_EXPIRY_SECONDS = 300  # 5 minutes


@app.get("/api/nonce")
async def get_nonce():
    """Generate a nonce for SIWE authentication."""
    import time

    nonce = secrets.token_urlsafe(16)
    nonce_store[nonce] = time.time()

    # Clean up expired nonces
    current_time = time.time()
    expired = [
        k for k, v in nonce_store.items() if current_time - v > NONCE_EXPIRY_SECONDS
    ]
    for k in expired:
        del nonce_store[k]

    return {"nonce": nonce}


@app.post("/api/verify")
async def verify_siwe(request: Request):
    """
    Verify SIWE signature and retrieve user's public key from enclave.

    The enclave generates and stores the PRE keypair.
    Client only receives the public key (sk NEVER leaves enclave).
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
            return {"status": "error", "message": "Invalid or expired nonce"}

        if time.time() - nonce_store[nonce] > NONCE_EXPIRY_SECONDS:
            del nonce_store[nonce]
            return {"status": "error", "message": "Nonce expired"}

        # Verify signature
        print(f"[EC2] Verifying SIWE for {siwe_message.address}")
        siwe_message.verify(signature)

        # Remove used nonce
        del nonce_store[nonce]

        address = siwe_message.address

        # Forward to enclave for registration/login
        # Enclave will generate keypair if new user, or return existing pk
        payload = json.dumps(
            {
                "action": "login",
                "address": address,
                "signature": signature,
                "message": message_str,
            }
        ).encode()

        response = await forward_enclave(payload)
        if not response:
            return {"status": "error", "message": "Failed to communicate with enclave"}

        try:
            data = json.loads(response.decode("utf-8"))
            return {
                "status": "success",
                "pk": data.get("public_key"),
                "verifying_key": data.get("verifying_key"),
                "address": address,
            }
        except (json.JSONDecodeError, UnicodeDecodeError):
            # Raw bytes response - encode as hex
            return {"status": "success", "pk": response.hex(), "address": address}

    except Exception as e:
        return {"status": "error", "message": f"Verification failed: {str(e)}"}


@app.post("/api/decrypt-capsule")
async def decrypt_capsule(request: Request):
    """
    Request enclave to decrypt a capsule using user's stored secret key.

    For owner's own files: decrypt directly
    For shared files: decrypt re-encrypted capsule (cfrag)

    Returns: The decrypted AES key (not the file contents)
    """
    try:
        body = await request.json()
        address = body.get("address")
        capsule_hex = body.get("capsule")  # Original or re-encrypted capsule
        cid = body.get("cid")
        is_reencrypted = body.get("is_reencrypted", False)
        owner_address = body.get("owner")  # Required for re-encrypted capsules

        if not address or not capsule_hex:
            return {"status": "error", "message": "Missing address or capsule"}

        # Verify on-chain access status if not the owner
        if cid and owner_address and address.lower() != owner_address.lower():
            try:
                contract, w3 = await get_contract()
                status = await contract.functions.getAccessStatus(cid, address).call()
                # AccessStatus enum: 0=NONE, 1=PENDING, 2=APPROVED, 3=DENIED
                if status != 2:
                    return {
                        "status": "error",
                        "message": "Access not approved on-chain",
                    }
            except Exception as e:
                print(f"Warning: Could not verify on-chain access: {e}")

        print(f"[EC2] Decrypt capsule request for {address}")
        # Forward to enclave for decryption
        payload = json.dumps(
            {
                "action": "decrypt_capsule",
                "address": address,
                "capsule": capsule_hex,
                "cid": cid,
                "is_reencrypted": is_reencrypted,
                "owner": owner_address,
                "signature": body.get("signature"),
                "message": body.get("message"),
            }
        ).encode()

        response = await forward_enclave(payload)
        if not response:
            return {"status": "error", "message": "Failed to communicate with enclave"}

        try:
            data = json.loads(response.decode("utf-8"))
            return data
        except (json.JSONDecodeError, UnicodeDecodeError):
            # Raw bytes = decrypted AES key
            return {"status": "success", "aes_key": response.hex()}

    except Exception as e:
        return {"status": "error", "message": f"Decryption failed: {str(e)}"}


@app.post("/login")
async def login(request: Request):
    """Handle user login via enclave."""
    try:
        body = await request.json()
        address = body.get("address")
        signature = body.get("signature", "")
        message = body.get("message", "")

        if not address:
            return {"status": "error", "message": "missing address"}
    except:
        return {"status": "error", "message": "invalid request body"}

    payload = json.dumps(
        {
            "action": "login",
            "address": address,
            "signature": signature,
            "message": message,
        }
    ).encode()

    response = await forward_enclave(payload)
    if response:
        try:
            data = json.loads(response.decode("utf-8"))
            return data
        except (json.JSONDecodeError, UnicodeDecodeError):
            return {
                "status": "success",
                "data": base64.b64encode(response).decode("ascii"),
            }
    else:
        return {"status": "error", "message": "Failed to communicate with enclave"}


@app.get("/api/capsule/{cid}")
async def get_capsule(cid: str, requester: str, owner: str):
    """Get re-encrypted capsule for a file."""
    print(f"[EC2] Get capsule request: cid={cid}, requester={requester}")
    redis = await get_redis()

    # Verify on-chain access status first
    try:
        contract, w3 = await get_contract()
        status = await contract.functions.getAccessStatus(cid, requester).call()
        # AccessStatus enum: 0=NONE, 1=PENDING, 2=APPROVED, 3=DENIED
        if status != 2:
            return {"status": "error", "message": "Access not approved on-chain"}
    except Exception as e:
        return {"status": "error", "message": f"Access verification failed: {e}"}

    # Fetch file data from blockchain
    try:
        file_data = await fetch_file_blockchain(cid)
        chain_owner = file_data[0]
        capsule = file_data[2]  # Now bytes from contract
        # Convert bytes to proper format if needed
        if isinstance(capsule, str):
            capsule = bytes.fromhex(capsule.replace("0x", ""))
        elif isinstance(capsule, bytes):
            pass  # Already bytes
        else:
            # It might be returned as a hex string with 0x prefix
            capsule = bytes(capsule)
    except Exception as e:
        return {"status": "error", "message": f"chain fetch failed: {e}"}

    if chain_owner.lower() != owner.lower():
        return {"status": "error", "message": "owner mismatch"}

    # Get re-encryption key
    rk = await get_rk(redis, owner, requester)
    if not rk:
        return {"status": "error", "message": "could not obtain re-encryption key"}

    # Get public keys for kfrag verification
    owner_pk_bytes = await get_public_key(redis, owner)
    requester_pk_bytes = await get_public_key(redis, requester)

    if not owner_pk_bytes:
        return {"status": "error", "message": "owner not registered in enclave"}
    if not requester_pk_bytes:
        return {"status": "error", "message": "requester not registered in enclave"}

    # Perform re-encryption
    try:
        reenc_capsule = await reencrypt_capsule(
            rk_bytes=rk,
            capsule_bytes=capsule,
            owner_pk_bytes=owner_pk_bytes,
            requester_pk_bytes=requester_pk_bytes,
        )
    except Exception as e:
        return {"status": "error", "message": f"reencryption failed: {e}"}

    return {
        "status": "success",
        "cid": cid,
        "owner": owner,
        "requester": requester,
        "reenc_capsule": base64.b64encode(reenc_capsule).decode("ascii"),
        "original_capsule": capsule.hex(),  # Include original capsule for decryption
    }


@app.post("/register")
async def register(request: Request):
    """Register a new user in the enclave."""
    try:
        body = await request.json()
        address = body.get("address")
        if not address:
            return {"status": "error", "message": "missing address"}
    except:
        return {"status": "error", "message": "invalid request body"}

    payload = json.dumps(
        {
            "action": "register",
            "address": address,
        }
    ).encode()

    response = await forward_enclave(payload)
    if response:
        try:
            data = json.loads(response.decode("utf-8"))
            return data
        except:
            return {
                "status": "success",
                "public_key": base64.b64encode(response).decode("ascii"),
            }
    return {"status": "error", "message": "failed to register user"}
