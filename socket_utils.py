import socket
import os

IS_LOCAL = os.getenv("IS_LOCAL_ENV", "False").lower() == "true"

def get_socket_type():
    if IS_LOCAL:
        return socket.AF_INET
    else:
        # AF_VSOCK is only available on Linux with vsock support
        if hasattr(socket, "AF_VSOCK"):
            return socket.AF_VSOCK
        else:
            raise RuntimeError("AF_VSOCK not available - ensure you're running on a Linux system with vsock support")
    
def get_connection_address(cid_or_host, port):
    """
    Get the connection address based on environment.
    
    Args:
        cid_or_host: For VSOCK, this is the CID (integer). For TCP, this is ignored.
        port: The port number to connect to.
    
    Returns:
        Tuple of (host/cid, port) appropriate for the socket type.
    """
    if IS_LOCAL:
        # For local development, use localhost or enclave hostname
        return ("127.0.0.1", port)
    else:
        # For VSOCK, CID must be an integer
        # CID 2 = host, CID 3 = parent (for nested VMs), enclave CID is assigned
        return (int(cid_or_host), port)