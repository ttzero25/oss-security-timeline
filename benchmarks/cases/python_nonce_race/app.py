used_nonces = set()


@app.post("/redeem")
async def redeem(request):
    nonce = request.json["nonce"]
    if nonce not in used_nonces:
        await apply_credit(request.user)
        used_nonces.add(nonce)
    return {"status": "processed"}
