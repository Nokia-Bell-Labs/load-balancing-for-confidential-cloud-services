#!/usr/bin/env python3
# © 2026 Nokia
# Licensed under the BSD 3-Clause Clear License
# SPDX-License-Identifier: BSD-3-Clause-Clear

"""Minimal streaming LLM inference server for the Janus CPU dry-run.

Serves the locally-staged Llama-3.1-8B-Instruct weights via HuggingFace
Transformers (CPU, AVX2-friendly) behind a token-streaming HTTP endpoint, so
time-to-first-token (TTFT) is directly measurable and the endpoint can be
fronted by Janus (dc_proxy) exactly like the web app and microservice.

This is the *dry-run* engine only: it validates model correctness, the TTFT
measurement path, and Janus fronting on a confidential CPU VM whose paravisor
masks AVX512 (so vLLM-CPU can't run). The real H100 run uses vLLM directly (see serve_vllm.py).

Endpoints:
  GET  /healthz                 -> {"ready": bool}
  POST /generate {prompt,max_tokens} -> text/event-stream of {"token": "..."}
                                        terminated by "data: [DONE]".

Run:  python3 serve_hf.py --model /home/janus/models/llama-3.1-8b-instruct \
        --bind 127.0.0.1 --port 8000 --dtype bfloat16
"""
import os
import argparse, json, threading, time

import torch
import uvicorn
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, StreamingResponse
from transformers import AutoModelForCausalLM, AutoTokenizer, TextIteratorStreamer

app = FastAPI()
STATE = {"tok": None, "model": None, "args": None}


def load_model(model_dir, dtype):
    t0 = time.time()
    dt = {"bfloat16": torch.bfloat16, "float16": torch.float16,
          "float32": torch.float32}[dtype]
    tok = AutoTokenizer.from_pretrained(model_dir)
    model = AutoModelForCausalLM.from_pretrained(
        model_dir, torch_dtype=dt, low_cpu_mem_usage=True)
    model.eval()
    STATE["tok"], STATE["model"] = tok, model
    print(f"[serve_hf] model loaded in {time.time()-t0:.1f}s (dtype={dtype})",
          flush=True)


@app.get("/healthz")
def healthz():
    return {"ready": STATE["model"] is not None}


@app.post("/generate")
async def generate(req: Request):
    body = await req.json()
    prompt = body.get("prompt", "")
    max_new = int(body.get("max_tokens", 64))
    tok, model = STATE["tok"], STATE["model"]
    if model is None:
        return JSONResponse({"error": "model not ready"}, status_code=503)

    # Build an instruct chat turn from the (ShareGPT) user prompt. transformers
    # 5.x returns a BatchEncoding dict here, so splat it into generate().
    messages = [{"role": "user", "content": prompt}]
    inputs = tok.apply_chat_template(
        messages, add_generation_prompt=True, return_tensors="pt",
        return_dict=True)

    streamer = TextIteratorStreamer(tok, skip_prompt=True,
                                    skip_special_tokens=True)
    gen_kwargs = dict(**inputs, streamer=streamer,
                      max_new_tokens=max_new, do_sample=False,
                      pad_token_id=tok.eos_token_id)

    def run():
        with torch.no_grad():
            model.generate(**gen_kwargs)

    def sse():
        th = threading.Thread(target=run, daemon=True)
        th.start()
        for text in streamer:
            if text:
                yield f"data: {json.dumps({'token': text})}\n\n"
        yield "data: [DONE]\n\n"

    return StreamingResponse(sse(), media_type="text/event-stream",
                             headers={"X-Accel-Buffering": "no",
                                      "Cache-Control": "no-cache"})


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--model", default=os.path.expanduser("~/models/llama-3.1-8b-instruct"))
    ap.add_argument("--bind", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=8000)
    ap.add_argument("--dtype", default="float32",
                    choices=["bfloat16", "float16", "float32"])
    ap.add_argument("--threads", type=int, default=0,
                    help="torch CPU threads (0 = leave default)")
    a = ap.parse_args()
    if a.threads:
        torch.set_num_threads(a.threads)
    STATE["args"] = a
    load_model(a.model, a.dtype)
    uvicorn.run(app, host=a.bind, port=a.port, log_level="warning")


if __name__ == "__main__":
    main()
