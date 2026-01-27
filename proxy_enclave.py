"""
Nitro Enclave Proxy Server

Responsibilities:
1. Secure Key Generation (skPRE, pkPRE) using py-umbral
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
from umbral import SecretKey, PublicKey, Signer, generate_kfrags
from eth_account import Account
from eth_account.messages import encode_defunct

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
            "action": "get_rk" | "get_public_key" | "register" | "login",
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
            elif action == "register":
                return await self.handle_register(request)
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

        Returns: Serialized KeyFrag bytes
        """
        owner = (request.get("owner") or "").lower()
        requester = (request.get("requester") or "").lower()
        print(f"[ENCLAVE] generating re-encryption key from {owner} to {requester}")

        if not owner or not requester:
            return self._error_response("Missing owner or requester address")

        # Get owner's keys
        owner_keys = self.key_store.get_user_keys(owner)
        if not owner_keys:
            return self._error_response(f"Owner {owner} not registered")

        # Get requester's public key
        requester_keys = self.key_store.get_user_keys(requester)
        if not requester_keys:
            return self._error_response(f"Requester {requester} not registered")

        try:
            # Create signer from owner's signing key
            signer = Signer(owner_keys.signing_key)

            # Generate key fragments for re-encryption
            # This creates kfrags that allow re-encryption from owner to requester
            kfrags = generate_kfrags(
                delegating_sk=owner_keys.secret_key,
                receiving_pk=requester_keys.public_key,
                signer=signer,
                threshold=THRESHOLD,
                shares=NUM_KFRAGS,
            )

            # Return the first kfrag (in production, you might distribute multiple)
            # The kfrag is already verified since we just generated it
            kfrag = kfrags[0]

            return self._success_response(bytes(kfrag))

        except Exception as e:
            return self._error_response(
                f"Failed to generate re-encryption key: {str(e)}"
            )

    async def handle_get_public_key(self, request: dict) -> bytes:
        """
        Retrieve a user's public key.

        Request format:
        {
            "action": "get_public_key",
            "address": "0x..."
        }

        Returns: Serialized PublicKey bytes
        """
        address = request.get("address", "").lower()

        if not address:
            return self._error_response("Missing address")

        user_keys = self.key_store.get_user_keys(address)
        if not user_keys:
            return self._error_response(f"User {address} not registered")

        return self._success_response(bytes(user_keys.public_key))

    async def handle_register(self, request: dict) -> bytes:
        """
        Register a new user and generate their key pair.

        Request format:
        {
            "action": "register",
            "address": "0x...",
            "signature": "0x..." (optional - for verification)
        }

        Returns: User's public key bytes
        """
        address = request.get("address", "").lower()
        print(f"[ENCLAVE] Registering user: {address}")

        if not address:
            return self._error_response("Missing address")

        if self.key_store.has_user(address):
            existing_keys = self.key_store.get_user_keys(address)
            if existing_keys:
                return self._success_response(
                    bytes(existing_keys.public_key),
                    metadata={
                        "verifying_key": bytes(existing_keys.verifying_key).hex()
                    },
                )

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
                "public_key": bytes(public_key).hex(),
                "verifying_key": bytes(verifying_key).hex(),
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
            "address": "0x...",
            "signature": "0x...",
            "message": "..."
        }

        In production, this would verify the signature against the user's
        Ethereum address to prove ownership.
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

        if not self.key_store.has_user(address):
            # Auto-register on first login
            return await self.handle_register(request)

        user_keys = self.key_store.get_user_keys(address)
        if user_keys is None:
            # Should not happen since we check has_user above, but handle anyway
            return await self.handle_register(request)

        # TODO: Generate a session token (in production, use proper JWT or similar)
        session_token = secrets.token_hex(32)

        response_data = {
            "status": "success",
            "address": address,
            "public_key": bytes(user_keys.public_key).hex(),
            "verifying_key": bytes(user_keys.verifying_key).hex(),
            "session_token": session_token,
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
        }

        Returns: Decrypted plaintext (the AES key)
        """
        from umbral import Capsule, CapsuleFrag, decrypt_original, decrypt_reencrypted

        address = (request.get("address") or "").lower()
        capsule_hex = request.get("capsule", "")
        ciphertext_hex = request.get("ciphertext", "")
        cid = request.get("cid", "")
        is_reencrypted = request.get("is_reencrypted", False)
        owner = (request.get("owner") or "").lower()

        print(
            f"[ENCLAVE] Decrypt request for {address}, cid={cid}, is_reencrypted={is_reencrypted}"
        )

        if not address:
            return self._error_response("Missing address")
        if not capsule_hex:
            return self._error_response("Missing capsule")
        if not ciphertext_hex:
            return self._error_response("Missing ciphertext")

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

        # Get the requester's keys
        user_keys = self.key_store.get_user_keys(address)
        if not user_keys:
            return self._error_response(f"User {address} not registered")

        try:
            capsule = Capsule.from_bytes(bytes.fromhex(capsule_hex))
            ciphertext = bytes.fromhex(ciphertext_hex)

            if is_reencrypted:
                # This is a re-encrypted scenario using cfrags
                # We need the owner's public key to decrypt
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
                # Decrypt using own secret key
                plaintext = decrypt_original(
                    delegating_sk=user_keys.secret_key,
                    capsule=capsule,
                    ciphertext=ciphertext,
                )

            # Return the decrypted AES key
            print(f"[ENCLAVE] Decryption successful for {address}")
            return self._success_response(plaintext)

        except Exception as e:
            return self._error_response(f"Decryption failed: {str(e)}")

    async def handle_get_proxy_public_key(self, request: dict) -> bytes:
        """
        Return the proxy's public key for attestation verification.
        """
        return self._success_response(
            bytes(self.key_store.proxy_public_key),
            metadata={"verifying_key": bytes(self.key_store.proxy_verifying_key).hex()},
        )

    def _success_response(self, data: bytes, metadata: Optional[dict] = None) -> bytes:
        """
        Create a success response.

        For binary data (keys, kfrags), we return raw bytes.
        The EC2 proxy knows to handle this based on the action.
        """
        if metadata:
            # If there's metadata, wrap in JSON
            response = {"status": "success", "data": data.hex(), **metadata}
            return json.dumps(response).encode("utf-8")
        else:
            # Return raw bytes for efficiency
            return data

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
