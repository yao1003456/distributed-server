"""
Nitro Enclave Proxy Server

Responsibilities:
1. Secure Key Generation (skPRE, pkPRE) using umbral-pre
2. Secure storage (Sealed Memory) of user private keys
3. Re-encryption key generation (rkA→B) upon verified request
4. TLS Termination (logical) for secure client communication

This runs inside an AWS Nitro Enclave and communicates with the EC2 host via VSOCK.
"""

import asyncio
import json
import os
import hashlib
import secrets
from typing import Optional
from dataclasses import dataclass, field
from umbral_pre import (
    SecretKey,
    PublicKey,
    Signer,
    generate_kfrags,
    Capsule,
    CapsuleFrag,
    decrypt_original,
    decrypt_reencrypted,
    encrypt,
)
from eth_account import Account
from eth_account.messages import encode_defunct
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.backends import default_backend

# VSOCK Configuration
VSOCK_PORT = 12345
VSOCK_CID_ANY = 0xFFFFFFFF  # Listen on any CID (VMADDR_CID_ANY)

# Enclave configuration
THRESHOLD = 1  # Number of kfrags needed to reconstruct (N of M threshold scheme)
NUM_KFRAGS = 1  # Total number of kfrags to generate


@dataclass
class UserKeyPair:
    """Stores a user's key pair securely in enclave memory."""

    secret_key: SecretKey
    public_key: PublicKey
    signing_key: SecretKey
    verifying_key: PublicKey


@dataclass
class SecureKeyStore:
    """
    Secure in-memory key storage for the enclave.

    In a production environment, this would use:
    - AWS Nitro Enclaves KMS integration for key derivation
    - Attestation-based key release
    - Encrypted persistence via parent instance
    """

    # Maps user address (lowercase) to their key pair
    user_keys: dict[str, UserKeyPair] = field(default_factory=dict)

    # PRE proxy's own key pair for signing attestations
    proxy_secret_key: SecretKey = field(default_factory=SecretKey.random)
    proxy_public_key: PublicKey = field(init=False)
    proxy_signing_key: SecretKey = field(default_factory=SecretKey.random)
    proxy_verifying_key: PublicKey = field(init=False)

    def __post_init__(self):
        self.proxy_public_key = self.proxy_secret_key.public_key()
        self.proxy_verifying_key = self.proxy_signing_key.public_key()

    def get_user_keys(self, address: str) -> Optional[UserKeyPair]:
        """Retrieve user's key pair by address."""
        return self.user_keys.get(address.lower())

    def store_user_keys(self, address: str, key_pair: UserKeyPair) -> None:
        """Store user's key pair."""
        self.user_keys[address.lower()] = key_pair

    def has_user(self, address: str) -> bool:
        """Check if user exists in key store."""
        return address.lower() in self.user_keys

    def remove_user(self, address: str) -> bool:
        """Remove user from key store."""
        address = address.lower()
        if address in self.user_keys:
            del self.user_keys[address]
            return True
        return False


class EnclaveServer:
    """
    Main enclave server handling cryptographic operations.
    """

    def __init__(self):
        self.key_store = SecureKeyStore()
        self.is_local = os.getenv("IS_LOCAL_ENV", "False").lower() == "true"

    async def handle_request(self, data: bytes) -> bytes:
        """
        Route incoming requests to appropriate handlers.

        Expected JSON format:
        {
            "action": "get_rk" | "get_public_key" | "login",
            ...action-specific fields
        }
        """
        try:
            request = json.loads(data.decode("utf-8"))
            action = request.get("action")
            print(f"[ENCLAVE] Received action: {action}")

            if action == "get_rk":
                return await self.handle_get_rk(request)
            elif action == "get_public_key":
                return await self.handle_get_public_key(request)
            elif action == "login":
                return await self.handle_login(request)
            elif action == "get_proxy_public_key":
                return await self.handle_get_proxy_public_key(request)
            elif action == "decrypt_capsule":
                return await self.handle_decrypt_capsule(request)
            else:
                return self._error_response(f"Unknown action: {action}")

        except json.JSONDecodeError as e:
            return self._error_response(f"Invalid JSON: {str(e)}")
        except Exception as e:
            return self._error_response(f"Internal error: {str(e)}")

    async def handle_get_rk(self, request: dict) -> bytes:
        """
        Generate re-encryption key fragment from owner to requester.

        Request format:
        {
            "action": "get_rk",
            "owner": "0x...",
            "requester": "0x..."
        }

        Returns: Serialized VerifiedKeyFrag bytes
        """
        owner = (request.get("owner") or "").lower()
        requester = (request.get("requester") or "").lower()
        print(f"[ENCLAVE] generating re-encryption key from {owner} to {requester}")

        if not owner or not requester:
            return self._error_response("Missing owner or requester address")
        try:
            # NOTE: Redis is not available in the enclave. This is a placeholder, a is simulated here
            # TODO: implement a secure external cache or a simulated cache for local testing

            owner_keys = self.key_store.get_user_keys(owner.lower())
            requester_keys = self.key_store.get_user_keys(requester.lower())

            if not owner_keys or not requester_keys:
                return self._error_response("Owner or requester not registered")

            signer = Signer(owner_keys.signing_key)

            kfrags = generate_kfrags(
                delegating_sk=owner_keys.secret_key,
                receiving_pk=requester_keys.public_key,
                signer=signer,
                threshold=THRESHOLD,
                shares=NUM_KFRAGS,
                sign_delegating_key=True,
                sign_receiving_key=True,
            )

            kfrag_bytes = bytes(kfrags[0])

            return self._success_response(kfrag_bytes)

        except Exception as e:
            print(f"Error generating RK: {e}")
            return self._error_response(f"Failed to generate RK: {str(e)}")

    async def handle_get_public_key(self, request: dict) -> bytes:
        """
        Retrieve a user's public key and verifying key.

        Request format:
        {
            "action": "get_public_key",
            "address": "0x..."
        }

        Returns: JSON with public_key and verifying_key (hex-encoded)
        """
        address = request.get("address", "").lower()

        if not address:
            return self._error_response("Missing address")

        user_keys = self.key_store.get_user_keys(address)
        if not user_keys:
            return self._error_response(f"User {address} not registered")

        response = {
            "status": "success",
            "public_key": user_keys.public_key.to_compressed_bytes().hex(),
            "verifying_key": user_keys.verifying_key.to_compressed_bytes().hex(),
        }
        return json.dumps(response).encode("utf-8")

    async def handle_register(self, request: dict) -> bytes:
        """
        Register a new user and generate their key pair.

        Request format:
        {
            "action": "register",
            "address": "0x...", (wallet address)
        }

        Returns: User's public key bytes
        """
        address = request.get("address", "").lower()
        print(f"[ENCLAVE] Registering user: {address}")

        if not address:
            return self._error_response("Missing address")

        try:
            # Generate new key pair for user
            secret_key = SecretKey.random()
            public_key = secret_key.public_key()

            # Generate signing key pair
            signing_key = SecretKey.random()
            verifying_key = signing_key.public_key()

            key_pair = UserKeyPair(
                secret_key=secret_key,
                public_key=public_key,
                signing_key=signing_key,
                verifying_key=verifying_key,
            )

            self.key_store.store_user_keys(address, key_pair)

            response = {
                "status": "success",
                "address": address,
                "public_key": public_key.to_compressed_bytes().hex(),
                "verifying_key": verifying_key.to_compressed_bytes().hex(),
            }
            return json.dumps(response).encode("utf-8")

        except Exception as e:
            return self._error_response(f"Registration failed: {str(e)}")

    async def handle_login(self, request: dict) -> bytes:
        """
        Handle user login/authentication.

        Request format:
        {
            "action": "login",
            "address": "0x..."(wallet address),
            "signature": "0x..."(wallet signature of message),
            "message": "..."(message signed by wallet)
        }
        """
        address = request.get("address", "").lower()
        signature = request.get("signature", "")
        message = request.get("message", "")
        print(f"[ENCLAVE] Login attempt for {address}")

        if not address:
            return self._error_response("Missing address")

        # Verify Ethereum signature
        if not self._verify_signature(address, message, signature):
            return self._error_response("Invalid signature")

        # create user if not exists, else return user keys
        if not self.key_store.has_user(address):
            return await self.handle_register(request)

        user_keys = self.key_store.get_user_keys(address)

        if user_keys is None:
            return self._error_response("User keys not found")

        # NOTE: maybe implement session token if theres time

        response_data = {
            "status": "success",
            "address": address,
            "public_key": user_keys.public_key.to_compressed_bytes().hex(),
            "verifying_key": user_keys.verifying_key.to_compressed_bytes().hex(),
        }

        print(f"[ENCLAVE] Login successful for {address}")
        return json.dumps(response_data).encode("utf-8")

    async def handle_decrypt_capsule(self, request: dict) -> bytes:
        """
        Decrypt a capsule using the user's stored secret key.

        This is the ONLY way for clients to get the decrypted AES key.
        The secret key never leaves the enclave.

        Request format:
        {
            "action": "decrypt_capsule",
            "address": "0x...",  # User requesting decryption
            "capsule": "hex...",  # Serialized capsule
            "ciphertext": "hex...",  # Encrypted data (the AES key encrypted with umbral)
            "cid": "hex...",  # CID of the file being decrypted
            "is_reencrypted": false,  # True if using re-encrypted cfrags
            "cfrag": "hex...",  # Required if is_reencrypted=true - the CapsuleFrag
            "owner": "0x..."  # Required if is_reencrypted=true
            "signature": "0x..." (wallet signature of message)
            "message": "..." (message signed by wallet)
        }

        Returns: Decrypted plaintext (the AES key)
        """
        address = (request.get("address") or "").lower()
        capsule_hex = request.get("capsule", "")
        ciphertext_hex = request.get("ciphertext", "")
        cid = request.get("cid", "")
        is_reencrypted = request.get("is_reencrypted", False)
        owner = (request.get("owner") or "").lower()
        ephemeral_public_key_hex = request.get("ephemeral_public_key")

        print(
            f"[ENCLAVE] Decrypt request for {address}, cid={cid}, is_reencrypted={is_reencrypted}"
        )

        if not address:
            return self._error_response("Missing address")
        if not capsule_hex:
            return self._error_response("Missing capsule")
        if not ciphertext_hex:
            return self._error_response("Missing ciphertext")
        if not ephemeral_public_key_hex:
            return self._error_response(
                "Missing ephemeral_public_key for secure channel"
            )

        # Verify intent to decrypt
        signature = request.get("signature")
        message = request.get("message")

        if not signature or not message:
            return self._error_response("Missing signature or message")

        if not self._verify_signature(address, message, signature):
            return self._error_response("Invalid signature for decryption")

        # Verify Message Binding to CID (Replay Protection)
        # TODO: fix replay protection logic, this may not be secure
        if cid:
            # Message format: "Sign to decrypt file: <CID>"
            if not message.strip().endswith(cid):
                print(
                    f"[ENCLAVE] Replay Attack Detected! Message '{message}' does not match CID '{cid}'"
                )
                return self._error_response(
                    "Invalid signature binding. Message does not match file CID."
                )
        else:
            print(
                "[ENCLAVE] Warning: CID signature binding check skipped (CID missing in payload) for decryption"
            )

        # Verify binding of ephemeral key to the signature to prevent MITM
        # The message signed by the wallet MUST contain the ephemeral public key
        # Message format: "Sign to decrypt file: <CID> with key: <EPHEMERAL_KEY>"
        # For POC we will just check if it's in the message string
        if ephemeral_public_key_hex not in message:
            print(
                "[ENCLAVE] Warning: Ephemeral key not bound to signature! MITM possible."
            )
            # In production, strict format checking is required.
            # return self._error_response("Ephemeral key not signed")

        # Get the requester's keys
        user_keys = self.key_store.get_user_keys(address)
        if not user_keys:
            return self._error_response(f"User {address} not registered")

        try:
            capsule = Capsule.from_bytes(bytes.fromhex(capsule_hex))
            ciphertext = bytes.fromhex(ciphertext_hex)

            if is_reencrypted:
                if not owner:
                    return self._error_response(
                        "Owner address required for re-encrypted capsule"
                    )

                owner_keys = self.key_store.get_user_keys(owner)
                if not owner_keys:
                    return self._error_response(f"Owner {owner} not registered")

                # Get the cfrag from the request
                cfrag_hex = request.get("cfrag", "")
                if not cfrag_hex:
                    return self._error_response(
                        "CapsuleFrag required for re-encrypted decryption"
                    )

                # Deserialize the capsule frag
                cfrag = CapsuleFrag.from_bytes(bytes.fromhex(cfrag_hex))

                # Verify the cfrag before using it
                verified_cfrag = cfrag.verify(
                    capsule=capsule,
                    verifying_pk=owner_keys.verifying_key,
                    delegating_pk=owner_keys.public_key,
                    receiving_pk=user_keys.public_key,
                )

                # Decrypt re-encrypted capsule
                plaintext = decrypt_reencrypted(
                    receiving_sk=user_keys.secret_key,
                    delegating_pk=owner_keys.public_key,
                    capsule=capsule,
                    verified_cfrags=[verified_cfrag],
                    ciphertext=ciphertext,
                )
            else:
                # Direct decryption (owner decrypting their own file)
                plaintext = decrypt_original(
                    delegating_sk=user_keys.secret_key,
                    capsule=capsule,
                    ciphertext=ciphertext,
                )

            # Return the decrypted AES key
            print(f"[ENCLAVE] Decryption successful for {address}")

            # Establish Secure Channel via ECDH
            try:
                shared_key = self._derive_shared_key(ephemeral_public_key_hex)
                encrypted_response = self._encrypt_response(plaintext, shared_key)
                return json.dumps(encrypted_response).encode("utf-8")
            except Exception as e:
                print(f"[ENCLAVE] Secure channel error: {e}")
                return self._error_response(f"Secure channel establishment failed: {e}")

        except Exception as e:
            return self._error_response(f"Decryption failed: {str(e)}")

    async def handle_get_proxy_public_key(self, request: dict) -> bytes:
        """
        Return the proxy's public key for attestation verification.
        """
        return self._success_response(
            self.key_store.proxy_public_key.to_compressed_bytes(),
            metadata={
                "verifying_key": self.key_store.proxy_verifying_key.to_compressed_bytes().hex()
            },
        )

    def _success_response(self, data: bytes, metadata: Optional[dict] = None) -> bytes:
        """
        Create a success response.

        Always returns JSON with hex-encoded data for consistency.
        This eliminates parsing ambiguity in the EC2 proxy.
        """
        response = {"status": "success", "data": data.hex()}
        if metadata:
            response.update(metadata)
        return json.dumps(response).encode("utf-8")

    def _verify_signature(
        self, address: str, message_text: str, signature: str
    ) -> bool:
        """Verify Ethereum signature recovers to address."""
        try:
            from eth_account import Account
            from eth_account.messages import encode_defunct

            if not message_text or not signature:
                return False

            msg = encode_defunct(text=message_text)
            recovered = Account.recover_message(msg, signature=signature)
            return recovered.lower() == address.lower()
        except Exception as e:
            print(f"Signature verification failed: {e}")
            return False

    def _error_response(self, message: str) -> bytes:
        """Create an error response."""
        response = {"status": "error", "message": message}
        return json.dumps(response).encode("utf-8")

    def _derive_shared_key(self, peer_public_key_hex: str) -> bytes:
        """
        Derive a shared session key using ECDH (Enclave Ephemeral Private Key + Peer Ephemeral Public Key).
        """
        # 1. Parse client's ephemeral public key
        # (Client sends raw uncompressed bytes hex-encoded, possibly with 0x prefix)
        if peer_public_key_hex.startswith("0x"):
            peer_public_key_hex = peer_public_key_hex[2:]

        peer_public_bytes = bytes.fromhex(peer_public_key_hex)

        # Load it as an EC public key (SECP256R1/P-256)
        peer_public_key = ec.EllipticCurvePublicKey.from_encoded_point(
            ec.SECP256R1(), peer_public_bytes
        )

        # 2. Generate Enclave's Ephemeral Key Pair
        enclave_private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
        enclave_public_key = enclave_private_key.public_key()

        # 3. Perform ECDH
        shared_secret = enclave_private_key.exchange(ec.ECDH(), peer_public_key)

        # 4. Derive Session Key using HKDF
        derived_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,  # AES-256
            salt=None,
            info=b"distributed-data-management-secure-channel",
            backend=default_backend(),
        ).derive(shared_secret)

        # Store the enclave's pub key to send back
        self.last_enclave_ephemeral_pub = enclave_public_key.public_bytes(
            encoding=serialization.Encoding.X962,
            format=serialization.PublicFormat.UncompressedPoint,
        )

        return derived_key

    def _encrypt_response(self, plaintext_data: bytes, key: bytes) -> dict:
        """Encrypt the response data using AES-GCM."""
        # Use AES-GCM for authenticated encryption
        aesgcm = AESGCM(key)
        nonce = os.urandom(12)
        ciphertext = aesgcm.encrypt(nonce, plaintext_data, None)

        return {
            "status": "success",
            "encrypted_data": ciphertext.hex(),
            "iv": nonce.hex(),
            "enclave_ephemeral_public_key": self.last_enclave_ephemeral_pub.hex(),
        }


class VSockServer:
    """
    VSOCK server for communication with EC2 parent instance.

    Uses length-prefixed messages:
    - 4 bytes: message length (big-endian)
    - N bytes: message payload
    """

    def __init__(self, enclave_server: EnclaveServer):
        self.enclave_server = enclave_server
        self.is_local = os.getenv("IS_LOCAL_ENV", "False").lower() == "true"

    async def handle_client(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ):
        """Handle a single client connection."""
        peer = writer.get_extra_info("peername")
        print(f"New connection from {peer}")

        try:
            while True:
                # Read message length (4 bytes, big-endian)
                length_bytes = await reader.readexactly(4)
                message_length = int.from_bytes(length_bytes, "big")
                print(f"[ENCLAVE] Received message length: {message_length}")

                if message_length <= 0 or message_length > 10 * 1024 * 1024:  # Max 10MB
                    print(f"Invalid message length: {message_length}")
                    break

                # Read message payload
                payload = await reader.readexactly(message_length)

                # Process request
                response = await self.enclave_server.handle_request(payload)

                # Send response with length prefix
                response_length = len(response).to_bytes(4, "big")
                writer.write(response_length + response)
                await writer.drain()

        except Exception as e:
            print(f"Error handling client {peer}: {e}")
        finally:
            writer.close()
            await writer.wait_closed()
            print(f"Connection closed: {peer}")

    async def start(self):
        """Start the VSOCK server."""
        if self.is_local:
            # Local development: use TCP
            server = await asyncio.start_server(
                self.handle_client, host="127.0.0.1", port=VSOCK_PORT
            )
            addr = server.sockets[0].getsockname()
            print(f"Enclave server running on TCP {addr}")
        else:
            # Production: use VSOCK
            import socket as sock_module

            if not hasattr(sock_module, "AF_VSOCK"):
                raise RuntimeError(
                    "AF_VSOCK not available - ensure you're running inside a Nitro Enclave"
                )

            # Create VSOCK socket
            sock = sock_module.socket(sock_module.AF_VSOCK, sock_module.SOCK_STREAM)  # type: ignore
            sock.setsockopt(sock_module.SOL_SOCKET, sock_module.SO_REUSEADDR, 1)
            sock.bind((VSOCK_CID_ANY, VSOCK_PORT))
            sock.listen(128)
            sock.setblocking(False)

            server = await asyncio.start_server(self.handle_client, sock=sock)
            print(f"Enclave server running on VSOCK port {VSOCK_PORT}")

        async with server:
            await server.serve_forever()


async def main():
    """Main entry point for the enclave server."""
    print("=" * 50)
    print("Starting Nitro Enclave Proxy Server")
    print("=" * 50)

    is_local = os.getenv("IS_LOCAL_ENV", "False").lower() == "true"
    if is_local:
        print("Running in LOCAL development mode (TCP)")
    else:
        print("Running in PRODUCTION mode (VSOCK)")

    # Initialize the enclave server
    enclave_server = EnclaveServer()

    # Start the VSOCK server
    vsock_server = VSockServer(enclave_server)

    try:
        await vsock_server.start()
    except KeyboardInterrupt:
        print("\nShutting down enclave server...")


if __name__ == "__main__":
    asyncio.run(main())
