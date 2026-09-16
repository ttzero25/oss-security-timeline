import asyncio


used_nonces = set()
nonce_lock = asyncio.Lock()


@app.post("/redeem")
async def redeem(request):
    nonce = request.json["nonce"]
    async with nonce_lock:
        if nonce not in used_nonces:
            await apply_credit(request.user)
            used_nonces.add(nonce)
    return {"status": "processed"}
