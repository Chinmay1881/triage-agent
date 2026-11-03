from fastapi import FastAPI

app = FastAPI(title="triage-agent")


@app.get("/health")
async def health() -> dict[str, str]:
    # Liveness only: answers even if Mongo or Groq is down.
    return {"status": "ok"}
