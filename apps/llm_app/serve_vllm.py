#!/usr/bin/env python3
# © 2026 Nokia
# Licensed under the BSD 3-Clause Clear License
# SPDX-License-Identifier: BSD-3-Clause-Clear

"""GPU LLM inference server (the paper's stack) — vLLM behind the same
token-streaming /generate SSE interface as serve_hf.py, so the Janus fronts,
baseline /generate forwards, and the TTFT infrastructure all work unchanged.

Serves Llama-3.1-8B-Instruct (fp16) on the confidential H100 via vLLM's
AsyncLLMEngine. TTFT = time to the first streamed token.

Run:  python3 serve_vllm.py --model /home/janus/models/llama-3.1-8b-instruct \
        --bind 127.0.0.1 --port 8000
"""
import argparse, json, os

os.environ.setdefault("VLLM_USE_V1", "0")  # prefer the stable AsyncLLMEngine
# flashinfer's sampling kernel crashes on the confidential H100; fall back to
# the native PyTorch sampler. Also disable vLLM 0.22's bleeding-edge FP8
# DeepGEMM path (we serve fp16, no quantization).
os.environ.setdefault("VLLM_USE_FLASHINFER_SAMPLER", "0")
os.environ.setdefault("VLLM_USE_DEEP_GEMM", "0")
os.environ.setdefault("VLLM_USE_FLASHINFER_MOE_FP8", "0")

import uvicorn
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, StreamingResponse
from vllm import AsyncLLMEngine, AsyncEngineArgs, SamplingParams
from vllm.utils import random_uuid
from transformers import AutoTokenizer

app = FastAPI()
STATE = {"engine": None, "tok": None, "args": None}


@app.on_event("startup")
async def _startup():
    a = STATE["args"]
    STATE["tok"] = AutoTokenizer.from_pretrained(a.model)
    STATE["engine"] = AsyncLLMEngine.from_engine_args(AsyncEngineArgs(
        model=a.model, dtype=a.dtype, gpu_memory_utilization=0.9,
        max_model_len=4096, enforce_eager=True,
        # Disable prefix caching so every request does a full prefill — the
        # TTFT distribution is then identical across protocols (no order-
        # dependent cache hits when the same prompts are replayed per protocol).
        enable_prefix_caching=False))
    print("[serve_vllm] engine ready", flush=True)


@app.get("/healthz")
def healthz():
    return {"ready": STATE["engine"] is not None}


@app.post("/generate")
async def generate(req: Request):
    body = await req.json()
    prompt = body.get("prompt", "")
    max_new = int(body.get("max_tokens", 64))
    eng, tok = STATE["engine"], STATE["tok"]
    if eng is None:
        return JSONResponse({"error": "engine not ready"}, status_code=503)

    text = tok.apply_chat_template([{"role": "user", "content": prompt}],
                                   add_generation_prompt=True, tokenize=False)
    sp = SamplingParams(max_tokens=max_new, temperature=0.0)
    results = eng.generate(text, sp, random_uuid())

    async def sse():
        prev = ""
        async for out in results:
            t = out.outputs[0].text
            delta = t[len(prev):]
            prev = t
            if delta:
                yield f"data: {json.dumps({'token': delta})}\n\n"
        yield "data: [DONE]\n\n"

    return StreamingResponse(sse(), media_type="text/event-stream",
                             headers={"X-Accel-Buffering": "no",
                                      "Cache-Control": "no-cache"})


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--model", default=os.path.expanduser("~/models/llama-3.1-8b-instruct"))
    ap.add_argument("--bind", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=8000)
    ap.add_argument("--dtype", default="float16")
    STATE["args"] = ap.parse_args()
    uvicorn.run(app, host=STATE["args"].bind, port=STATE["args"].port,
                log_level="warning")


if __name__ == "__main__":
    main()
