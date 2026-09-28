async def llm_tool(prompt: str, model: str = "llama3.1") -> dict:
    import aiohttp
    async with aiohttp.ClientSession() as session:
        async with session.post(
            "http://localhost:11434/api/generate",
            json={"model": model, "prompt": prompt},
        ) as resp:
            data = await resp.json()
            return {"response": data.get("response", ""), "model": model}
