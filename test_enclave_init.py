import asyncio
import json
import base64


async def test_init():
    reader, writer = await asyncio.open_connection("127.0.0.1", 12345)

    # Test Init
    payload = json.dumps({"action": "init"}).encode()
    length_prefix = len(payload).to_bytes(4, "big")
    writer.write(length_prefix + payload)
    await writer.drain()

    length_bytes = await reader.readexactly(4)
    response_length = int.from_bytes(length_bytes, "big")
    data = await reader.readexactly(response_length)

    print(f"Response: {data.decode('utf-8')}")

    writer.close()
    await writer.wait_closed()


asyncio.run(test_init())
