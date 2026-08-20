#!/usr/bin/env python3
"""A browser test page for AVS. No HRM, no Next.js, no Java.

    python scripts/test_page.py

Then open http://127.0.0.1:8090 and upload two photos.

To test from a PHONE on the same wifi (this is the useful one):

    python scripts/test_page.py --host 0.0.0.0

then browse to http://<this-machine's-LAN-ip>:8090 from the phone.

⛔⛔ THE BROWSER TALKS DIRECTLY TO AVS HERE. THAT IS ONLY SAFE BECAUSE
    AUTHENTICATION IS OFF, AND IT MUST NEVER BE COPIED INTO PRODUCTION.

    In production, calling AVS requires an HMAC signature, and a browser cannot
    hold a signing secret — anything shipped to a client is public. Images go to
    the HRM, which signs server-side and forwards.

    This page exists to exercise the BROWSER half — the pre-check, the guidance
    wording, the polling — while the HRM backend is being finished. The page
    itself is throwaway; the logic it exercises is not.

★ WHY THIS IS WORTH RUNNING ON A PHONE

  `BarcodeDetector` has never executed on a real device anywhere in this
  project. It is the single largest untested assumption: the whole pre-check
  rests on it, and Chrome on Android is where it actually exists.

  A file input needs no HTTPS and no camera permission, so a plain LAN address
  is enough to find out.
"""

import argparse
import sys
import threading
import time
from pathlib import Path

from fastapi import FastAPI
from fastapi.responses import HTMLResponse

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "src"))

AVS_PORT = 8477
PAGE_PORT = 8090

PAGE = """<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>AVS test page</title>
<style>
 body{font:16px system-ui,sans-serif;max-width:640px;margin:0 auto;padding:20px;line-height:1.5}
 .warn{background:#fff3cd;border:1px solid #ffc107;padding:10px 14px;border-radius:6px;font-size:14px}
 .side{border:1px solid #ddd;border-radius:8px;padding:14px;margin:14px 0}
 img{max-width:150px;border-radius:6px;display:block;margin:8px 0}
 button{font-size:16px;padding:10px 18px;border-radius:6px;border:1px solid #888;background:#fff}
 button[disabled]{opacity:.45}
 .ok{color:#15803d;font-weight:600}.bad{color:#b45309}
 #verdict{font-size:22px;font-weight:700;margin-top:8px}
 pre{background:#f6f6f6;padding:10px;border-radius:6px;overflow:auto;font-size:12px}
</style></head><body>
<h2>Aadhaar upload — test page</h2>
<p class="warn"><b>Development only.</b> The browser is calling AVS directly
because authentication is off. Production must never do this: a browser cannot
hold a signing secret.</p>

<div class="side"><b>Front — or your whole Aadhaar PDF</b><br>
 <input type="file" id="f" accept="image/jpeg,image/png,image/heic,image/heif,application/pdf">
 <div id="fmsg"></div><img id="fimg" hidden></div>

<div class="side" id="backbox"><b>Back</b><br>
 <input type="file" id="b" accept="image/jpeg,image/png,image/heic,image/heif">
 <div id="bmsg"></div><img id="bimg" hidden></div>

<div class="side" id="pwbox" hidden><b>PDF password</b><br>
 <p style="font-size:14px;margin:6px 0">If the PDF is password-protected. For an
 e-Aadhaar it is the first 4 letters of your name in CAPITALS followed by your
 year of birth — for example RAME1990.</p>
 <input type="password" id="pw" autocomplete="off" style="font-size:16px;padding:6px">
</div>

<button id="go" disabled>Submit</button>
<div id="verdict"></div><div id="msg"></div>
<pre id="log"></pre>

<script>
const AVS = location.protocol + '//' + location.hostname + ':__AVS_PORT__';
const MODULES_ACROSS = 97, MIN_PX_PER_MODULE = 2.0, MIN_MEGAPIXELS = 2.0;
const files = {front:null, back:null};
const log = m => document.getElementById('log').textContent += m + "\\n";

// ⛔ The Secure QR is one very long decimal integer. A URL sticker or an app QR
//    will not match, and telling those apart is what lets the message say
//    "try the other side" instead of a baffling "no QR found".
const isSecureQr = t => /^\\d{100,}$/.test((t||'').trim());

async function precheck(file){
  const t0 = performance.now();
  const bmp = await createImageBitmap(file);
  const mp = (bmp.width*bmp.height)/1e6;
  let outcome='DETECTOR_UNAVAILABLE', qrPixels;

  if ('BarcodeDetector' in window){
    try{
      const codes = await new BarcodeDetector({formats:['qr_code']}).detect(bmp);
      const secure = codes.find(c => isSecureQr(c.rawValue));
      if (secure){
        outcome='SECURE_QR_READABLE';
        const bb = secure.boundingBox;
        if (bb) qrPixels = Math.round(Math.min(bb.width, bb.height));
      } else outcome = codes.length ? 'WRONG_QR_ON_THIS_FACE' : 'NO_QR_FOUND';
    }catch(e){ outcome='DETECTOR_UNAVAILABLE'; }
  }
  bmp.close && bmp.close();
  return {outcome, mp, qrPixels, ms: Math.round(performance.now()-t0),
          detector: ('BarcodeDetector' in window) ? 'BarcodeDetector' : 'none'};
}

function guidance(r){
  if (r.outcome === 'SECURE_QR_READABLE') return ['ok','✓ The code on this photo is readable.'];
  if (r.outcome === 'DETECTOR_UNAVAILABLE')
    return ['bad','This browser cannot check the photo here — you can still upload it.'];
  if (r.outcome === 'WRONG_QR_ON_THIS_FACE')
    return ['bad','This side has a code, but not the signed one. The other side may work.'];
  if (r.mp < MIN_MEGAPIXELS) return ['bad','This photo is low resolution. Use the full-quality original.'];
  if (r.qrPixels && r.qrPixels/MODULES_ACROSS < MIN_PX_PER_MODULE)
    return ['bad','The code is too small. Move closer so the card fills the frame.'];
  return ['bad','We could not read the code here. You can still upload it.'];
}

// Content, not extension — the same rule the server applies.
async function isPdf(file){
  try{
    const head = await file.slice(0,5).arrayBuffer();
    return new TextDecoder('latin1').decode(head) === '%PDF-';
  }catch(e){ return file.type === 'application/pdf'; }
}

let pdfMode = false;

async function pick(which, input, msgEl, imgEl){
  const file = input.files[0]; if(!file) return;

  // ★ A PDF is not an image. `createImageBitmap` cannot decode one, so running
  //   the image pre-check would report "we could not check this photo" on the
  //   BEST input we accept. Skipping is correct, not degraded.
  if (which === 'front' && await isPdf(file)){
    pdfMode = true;
    files.front = file; files.back = null;
    msgEl.className = 'ok';
    msgEl.textContent = 'PDF selected. The code will be read on the server.';
    imgEl.hidden = true;
    document.getElementById('backbox').hidden = true;
    document.getElementById('pwbox').hidden = false;
    log(`front: PDF ${(file.size/1024).toFixed(0)}KB — pre-check skipped`);
    document.getElementById('go').disabled = false;
    return;
  }

  if (which === 'front'){
    pdfMode = false;
    document.getElementById('backbox').hidden = false;
    document.getElementById('pwbox').hidden = true;
  }

  msgEl.textContent = 'Checking…';
  const r = await precheck(file);
  const [cls, text] = guidance(r);
  msgEl.className = cls; msgEl.textContent = text;
  imgEl.src = URL.createObjectURL(file); imgEl.hidden = false;
  files[which] = file;
  log(`${which}: ${r.outcome} detector=${r.detector} ${r.mp.toFixed(1)}MP `
      + `qr=${r.qrPixels||'-'}px ${r.ms}ms`);
  // ⛔ Upload is NEVER blocked by the pre-check. The server runs 23
  //    preprocessing variants the browser does not, and Safari has no detector.
  document.getElementById('go').disabled = !(files.front && files.back);
}

document.getElementById('f').onchange = e =>
  pick('front', e.target, fmsg, fimg);
document.getElementById('b').onchange = e =>
  pick('back', e.target, bmsg, bimg);

document.getElementById('go').onclick = async () => {
  const go = document.getElementById('go');
  go.disabled = true; document.getElementById('verdict').textContent = 'Uploading…';
  const fd = new FormData();
  fd.append('front', files.front);
  // ⛔ A PDF is submitted ALONE — its pages already carry both faces.
  if (!pdfMode && files.back) fd.append('back', files.back);
  const pw = document.getElementById('pw').value;
  if (pdfMode && pw) fd.append('password', pw);

  const t0 = performance.now();
  const res = await fetch(AVS + '/v1/verify/upload', {method:'POST', body:fd});
  const body = await res.json();
  log('submit -> ' + res.status + ' job ' + (body.job_id||''));
  if (res.status !== 202){
    document.getElementById('verdict').textContent = 'HTTP ' + res.status;
    document.getElementById('verdict').className = 'bad';
    document.getElementById('msg').textContent =
      (body.detail && (body.detail.user_message || body.detail.message)) || '';
    go.disabled = false; return;
  }

  let out = {};
  for (let i=0;i<200;i++){
    const p = await fetch(AVS + '/v1/verify/' + body.job_id);
    out = await p.json();
    if (['DONE','SUCCEEDED','FAILED','ERROR'].includes(out.status)) break;
    await new Promise(r=>setTimeout(r,500));
  }

  // ★ Reads the `decision` block — exactly what the HRM frontend will read,
  //   rather than re-deriving approval from the raw result.
  const d = out.decision || {};
  const result = out.result || {};
  document.getElementById('verdict').textContent =
    (d.status || result.verdict || out.status) + '  (' + (d.status_code||'') + ')';
  document.getElementById('verdict').className = d.status === 'APPROVED' ? 'ok' : 'bad';
  document.getElementById('msg').textContent = d.message || result.user_message || '';
  log(`status=${d.status} code=${d.status_code} verdict=${d.verdict} `
      + `sig=${d.signature_valid} review=${d.needs_review} `
      + `${Math.round(performance.now()-t0)}ms`);
  const sideErrors = (result.sides||[]).map(s=>s.error).filter(Boolean);
  if (sideErrors.length) log('side errors: ' + sideErrors.join(', '));
  go.disabled = false;
};

log('detector: ' + (('BarcodeDetector' in window) ? 'BarcodeDetector present'
    : 'NOT AVAILABLE in this browser'));
log('avs: ' + AVS);
</script></body></html>
"""


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", default="127.0.0.1", help="0.0.0.0 to reach it from a phone")
    parser.add_argument("--port", type=int, default=PAGE_PORT)
    parser.add_argument("--certs", type=Path, default=REPO_ROOT / "certs")
    arguments = parser.parse_args()

    import httpx
    import uvicorn

    from avs.api import create_app

    # ⚠ CORS must allow any origin here: the page is served from :8090 and calls
    #   AVS on :8477, and from a phone the host is a LAN IP nobody can predict.
    #   Acceptable ONLY because this is a throwaway local server.
    avs = create_app(
        cert_dir=str(arguments.certs),
        require_auth=False,
        audit_path=str(REPO_ROOT / "test_page_audit.jsonl"),
        time_budget_seconds=5.0,
    )
    from fastapi.middleware.cors import CORSMiddleware

    avs.add_middleware(
        CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"]
    )

    threading.Thread(
        target=uvicorn.Server(
            uvicorn.Config(avs, host=arguments.host, port=AVS_PORT, log_level="critical")
        ).run,
        daemon=True,
    ).start()

    probe = httpx.Client(base_url=f"http://127.0.0.1:{AVS_PORT}", timeout=30.0, trust_env=False)
    for _ in range(40):
        try:
            if probe.get("/health").status_code == 200:
                break
        except Exception:  # noqa: S110 — still booting
            pass
        time.sleep(0.5)
    else:
        print("⛔ AVS did not start")
        return 1

    certificates = probe.get("/ready").json().get("certificates", 0)

    page = FastAPI()

    @page.get("/", response_class=HTMLResponse)
    def index() -> str:
        return PAGE.replace("__AVS_PORT__", str(AVS_PORT))

    print("\n" + "=" * 72)
    print("  ⛔  TEST PAGE — DEVELOPMENT ONLY.")
    print("      The browser calls AVS directly because auth is OFF.")
    print("      Production must never do this: a browser cannot hold a secret.")
    print("=" * 72)
    print(f"\n  open        http://{arguments.host}:{arguments.port}")
    print(f"  AVS         http://{arguments.host}:{AVS_PORT}  ({certificates} certificate(s))")
    if not certificates:
        print(f"\n  ⚠ NO CERTIFICATES — every card returns ERROR. Add them to {arguments.certs}")
    if arguments.host == "0.0.0.0":  # noqa: S104 — deliberate, for phone testing
        print("\n  ★ Bound to all interfaces. From a phone on the same wifi, browse to")
        print(f"    http://<this machine's LAN IP>:{arguments.port}")
        print("    Chrome on Android is where BarcodeDetector actually exists.")
    print("\n  Ctrl+C to stop.\n")

    uvicorn.run(page, host=arguments.host, port=arguments.port, log_level="warning")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
