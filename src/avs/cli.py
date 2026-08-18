"""AVS command-line interface.

ARCHITECTURAL CONTRACT
----------------------
Built in : Step 0 (skeleton), extended each step
Provides : the `avs` console entry point
Consumes : avs.contracts, avs.config, avs.logging

Commands are added as their steps complete:
    Step 0  ✅ version · contracts · doctor
    Step 1  ✅ verify-qr · selftest
    Step 2  ✅ certs status · certs fingerprints
    Step 3  ✅ ingest
    Step 4  ✅ preprocess
    Step 5  ✅ decode · decoders
    Step 6  ✅ verify  🏁 Milestone A complete
    Step 7  ✅ serve
    Step 8  ✅ serve --tenants (HMAC auth)
    Step 9  ✅ certs pin · audit verify
    Step 12 ✅ models status · models pin
"""

from __future__ import annotations

import json
import time
from pathlib import Path

import typer
from rich.console import Console
from rich.table import Table

from avs import __contract_version__, __version__
from avs.config import get_settings
from avs.contracts import CardSide, CheckName, ErrorCode, Strictness, Verdict
from avs.crypto import SecureQrVerifier
from avs.imaging import STRATEGIES, PreprocessingVariantGenerator
from avs.ingest import ClamAvScanner, ImageIngestor, IngestError, detect
from avs.logging import configure_logging
from avs.parser import ParseError, SecureQrParser
from avs.pipeline import DocumentVerifier, SideInput
from avs.privacy import DataMinimisingFilter
from avs.qr import QrDecoderCascade, decoder_availability
from avs.truststore import (
    PIN_FILE_NAME,
    FileCertificateStore,
    TrustStoreError,
    UidaiCertificate,
)

app = typer.Typer(
    name="avs",
    help="Aadhaar Verification Service — UIDAI Secure QR signature verification.",
    no_args_is_help=True,
    add_completion=False,
)
console = Console()


@app.command()
def version() -> None:
    """Show the service and contract versions."""
    console.print(f"[bold]AVS[/bold] {__version__}")
    console.print(f"Contract version: {__contract_version__}")


@app.command()
def contracts() -> None:
    """Print the frozen contract surface — verdicts, checks, error codes.

    Useful for confirming that an implementation step has not drifted from
    CONTRACTS.md.
    """
    vt = Table(title="Verdicts (frozen — exactly 9)", header_style="bold")
    vt.add_column("Verdict")
    vt.add_column("Auto-approve", justify="center")
    vt.add_column("Human review", justify="center")
    vt.add_column("Retry", justify="center")
    for v in Verdict:
        vt.add_row(
            v.value,
            "[green]YES[/green]" if v.is_auto_approve else "—",
            "YES" if v.requires_human_review else "—",
            "YES" if v.allows_retry else "—",
        )
    console.print(vt)

    ct = Table(title="Checks (frozen)", header_style="bold")
    ct.add_column("Check")
    ct.add_column("Verdict-bearing", justify="center")
    ct.add_column("AI-produced", justify="center")
    for c in CheckName:
        ct.add_row(
            c.value,
            "[bold green]★ YES[/bold green]" if c.is_verdict_bearing else "—",
            "AI" if c.is_ai_produced else "—",
        )
    console.print(ct)

    console.print(f"\n[dim]{len(list(ErrorCode))} error codes defined.[/dim]")
    console.print(
        "\n[bold yellow]Rule 1[/bold yellow] VERIFIED is the only auto-approval, "
        "and requires signature_valid == True."
    )
    console.print(
        "[bold yellow]Rule 2[/bold yellow] Nothing is ever auto-rejected — "
        "every other outcome goes to retry or a human."
    )


@app.command()
def doctor() -> None:
    """Check the local environment and report which steps are implemented."""
    configure_logging(json_output=False)
    settings = get_settings()

    t = Table(title="Environment", header_style="bold")
    t.add_column("Setting")
    t.add_column("Value")
    t.add_row("environment", settings.environment)
    t.add_row("cert_dir", str(settings.cert_dir))
    t.add_row("cert_dir exists", "yes" if settings.cert_dir.exists() else "[red]no[/red]")
    t.add_row("signature_byte_length", str(settings.signature_byte_length))
    t.add_row("max_file_bytes", f"{settings.max_file_bytes:,}")
    t.add_row("allowed_mime_types", ", ".join(settings.allowed_mime_types))
    console.print(t)

    steps = Table(title="Build progress", header_style="bold")
    steps.add_column("Step")
    steps.add_column("Module")
    steps.add_column("Status")
    rows = [
        ("0", "contracts, config, logging", "DONE"),
        ("1", "parser, crypto", "DONE"),
        ("2", "truststore (full)", "DONE"),
        ("3", "ingest", "DONE"),
        ("4", "imaging", "DONE"),
        ("5", "qr", "DONE"),
        ("6", "rules, privacy, pipeline", "DONE"),
        ("7", "api, worker, storage", "DONE"),
    ]
    for step, module, status in rows:
        colour = {"DONE": "green", "PARTIAL": "yellow"}.get(status, "dim")
        steps.add_row(step, module, f"[{colour}]{status}[/{colour}]")
    console.print(steps)

    dec = Table(title="QR decoder backends", header_style="bold")
    dec.add_column("Backend")
    dec.add_column("Status")
    for name, ok in decoder_availability().items():
        dec.add_row(name, "[green]available[/green]" if ok else "[dim]unavailable[/dim]")
    console.print(dec)
    if not any(decoder_availability().values()):
        console.print("[bold red]No QR decoder available — nothing can decode.[/bold red]")

    console.print("\n[dim]See PROJECT_STATE.md for the full 25-step registry.[/dim]")


# --------------------------------------------------------------------------- #
# Step 1 commands
# --------------------------------------------------------------------------- #


@app.command("verify-qr")
def verify_qr(
    payload_file: Path = typer.Option(
        ...,
        "--file",
        "-f",
        help="File containing the decoded QR payload string. Using a file rather "
        "than an inline argument keeps the payload out of your shell history.",
        exists=True,
        dir_okay=False,
    ),
    cert_dir: Path = typer.Option(
        Path("certs"), "--certs", "-c", help="Directory of UIDAI certificates"
    ),
    show_fields: bool = typer.Option(
        False, "--show-fields", help="Print extracted demographics (masked)"
    ),
) -> None:
    """Parse and verify a Secure QR payload string.

    The payload is read from a file so it never appears in shell history or
    process listings.
    """
    configure_logging(json_output=False)

    certificates: list[UidaiCertificate] = []
    if cert_dir.exists():
        store = FileCertificateStore(cert_dir)
        store.load()
        certificates = store.certificates()
        for issue in store.issues:
            marker = "[red]REFUSED[/red]" if issue.fatal else "[yellow]skipped[/yellow]"
            console.print(f"{marker} {issue.filename}: {issue.reason}")

    if not certificates:
        console.print(
            f"[red]No UIDAI certificates found in {cert_dir}/[/red]\n"
            "[dim]Populate the trust store first — see certs/README.md. Without a "
            "trust anchor nothing can verify, which is the correct behaviour.[/dim]"
        )

    raw = payload_file.read_text(encoding="utf-8").strip()

    try:
        payload = SecureQrParser().parse(raw)
    except ParseError as exc:
        console.print(f"\n[bold red]PARSE FAILED[/bold red]  {exc.code.value}")
        console.print(f"[dim]{exc.message}[/dim]")
        if exc.is_legacy:
            console.print(
                "\n[yellow]This is a pre-2018 unsigned QR.[/yellow] It is not a "
                "forgery — it simply predates signing. Ask for a fresh e-Aadhaar."
            )
        raise typer.Exit(code=2) from exc

    proof = SecureQrVerifier(certificates).verify(payload)

    t = Table(title="Verification", header_style="bold")
    t.add_column("Property")
    t.add_column("Value")
    t.add_row("QR version", payload.version)
    t.add_row("Signed bytes", f"{proof.signed_byte_length:,}")
    t.add_row("Signature bytes", str(len(payload.signature)))
    t.add_row("Certificates tried", str(len(certificates)))
    t.add_row("Algorithm", proof.algorithm)
    if proof.valid:
        t.add_row("Certificate serial", proof.certificate_serial or "—")
    if proof.error:
        t.add_row("Error", proof.error.value)
    console.print(t)

    if show_fields:
        f = Table(title="Extracted (signed) fields", header_style="bold")
        f.add_column("Field")
        f.add_column("Value")
        f.add_row("Name", payload.identity.name)
        f.add_row("DOB", payload.identity.dob)
        f.add_row("Gender", payload.identity.gender)
        f.add_row("Aadhaar", f"XXXX XXXX {payload.identity.aadhaar_last4}")
        f.add_row("District", payload.address.district or "—")
        f.add_row("State", payload.address.state or "—")
        f.add_row("Pincode", payload.address.pincode or "—")
        f.add_row("Photo", f"{len(payload.photo):,} bytes" if payload.photo else "—")
        console.print(f)

    console.print()
    if proof.valid:
        console.print("[bold green]✓ SIGNATURE VALID — document is genuine[/bold green]")
    else:
        console.print("[bold red]✗ COULD NOT BE VERIFIED[/bold red]")
        console.print(
            "[dim]Note: say 'could not be verified', never 'fake'. A genuine card "
            "photographed badly is not a forgery. CONTRACTS.md §1.[/dim]"
        )
        raise typer.Exit(code=1)


@app.command("ingest")
def ingest_file(
    image_file: Path = typer.Argument(
        ..., help="Image file to validate", exists=True, dir_okay=False
    ),
    scan: bool = typer.Option(False, "--scan", help="Run a ClamAV scan (requires clamd)"),
    keep_metadata: bool = typer.Option(
        False, "--keep-metadata", help="Do NOT strip EXIF (forensic use only)"
    ),
) -> None:
    """Validate an image against the ingest security boundary.

    Shows exactly what is accepted, what is rejected, and why — useful for
    confirming behaviour before wiring uploads into the HRM.
    """
    configure_logging(json_output=False)

    raw = image_file.read_bytes()
    detected = detect(raw)

    d = Table(title="Detection", header_style="bold")
    d.add_column("Property")
    d.add_column("Value")
    d.add_row("Filename", image_file.name)
    d.add_row("Extension", image_file.suffix or "—")
    d.add_row("Size", f"{len(raw):,} bytes")
    d.add_row(
        "Detected type", detected.kind.value + (f" ({detected.detail})" if detected.detail else "")
    )
    d.add_row("MIME (from bytes)", detected.mime_type)
    d.add_row("Accepted", "[green]yes[/green]" if detected.is_accepted else "[red]no[/red]")
    console.print(d)

    if image_file.suffix and detected.is_accepted:
        claimed = image_file.suffix.lower().lstrip(".")
        if claimed in {"jpg", "jpeg"} and detected.kind.value != "jpeg":
            console.print(
                "[yellow]Note: the extension disagrees with the content. "
                "The content wins — extensions are never trusted.[/yellow]"
            )

    ingestor = ImageIngestor(
        scanner=ClamAvScanner() if scan else None,
        strip_metadata=not keep_metadata,
    )

    try:
        image = ingestor.ingest(raw, filename=image_file.name)
    except IngestError as exc:
        console.print(f"\n[bold red]REJECTED[/bold red]  {exc.code.value}")
        console.print(f"[dim]technical : {exc.message}[/dim]")
        console.print(f"employee  : {exc.user_message}")
        raise typer.Exit(code=1) from exc

    r = Table(title="Accepted", header_style="bold")
    r.add_column("Property")
    r.add_column("Value")
    r.add_row("Normalised MIME", image.mime_type)
    r.add_row("Dimensions", f"{image.width} x {image.height}")
    r.add_row("Megapixels", f"{image.width * image.height / 1_000_000:.1f}")
    r.add_row("Original size", f"{image.size_bytes:,} bytes")
    r.add_row("Normalised size", f"{len(image.data):,} bytes")
    r.add_row("SHA-256 (original)", image.sha256[:32] + "…")
    r.add_row("Metadata", "kept" if keep_metadata else "[green]stripped[/green]")
    r.add_row("Malware scan", "clamav" if scan else "[dim]skipped[/dim]")
    console.print(r)

    console.print("\n[bold green]✓ Accepted — safe to process[/bold green]")
    if not keep_metadata:
        console.print("[dim]All EXIF metadata was discarded, GPS coordinates included.[/dim]")


@app.command("preprocess")
def preprocess_file(
    image_file: Path = typer.Argument(..., help="Image to preprocess", exists=True, dir_okay=False),
    out_dir: Path = typer.Option(
        None, "--out", "-o", help="Write each variant as a PNG for visual inspection"
    ),
    max_tier: int = typer.Option(4, "--max-tier", help="Skip strategies above this cost tier"),
    limit: int = typer.Option(0, "--limit", help="Stop after N variants (0 = no limit)"),
    no_warp: bool = typer.Option(False, "--no-warp", help="Skip perspective correction"),
) -> None:
    """Generate preprocessing variants and report cost per strategy.

    With --out, each variant is written as a PNG so you can see exactly what the
    QR decoder will be handed. That is the fastest way to understand why a
    particular photo fails to decode.
    """
    configure_logging(json_output=False)

    try:
        image = ImageIngestor().ingest(image_file.read_bytes(), filename=image_file.name)
    except IngestError as exc:
        console.print(f"[bold red]REJECTED at ingest[/bold red]  {exc.code.value}")
        console.print(f"[dim]{exc.message}[/dim]")
        raise typer.Exit(code=1) from exc

    generator = PreprocessingVariantGenerator(
        max_tier=max_tier,
        limit=limit or None,
        enable_warp=not no_warp,
    )
    tier_of = {s.name: s.tier for s in STRATEGIES}

    if out_dir:
        out_dir.mkdir(parents=True, exist_ok=True)

    t = Table(title=f"Variants for {image_file.name}", header_style="bold")
    t.add_column("#", justify="right")
    t.add_column("Strategy")
    t.add_column("Tier", justify="center")
    t.add_column("Size", justify="right")
    t.add_column("Cumulative ms", justify="right")

    start = time.perf_counter()
    total_bytes = 0
    count = 0

    for index, variant in enumerate(generator.generate(image), start=1):
        elapsed_ms = (time.perf_counter() - start) * 1000
        total_bytes += len(variant.data)
        count = index
        t.add_row(
            str(index),
            variant.strategy,
            str(tier_of.get(variant.strategy, "?")),
            f"{len(variant.data):,}",
            f"{elapsed_ms:.0f}",
        )
        if out_dir:
            (out_dir / f"{index:02d}_{variant.strategy.replace('+', '_')}.png").write_bytes(
                variant.data
            )

    console.print(t)
    total_ms = (time.perf_counter() - start) * 1000
    console.print(f"\n{count} variants · {total_bytes:,} bytes · {total_ms:.0f} ms total")
    console.print(
        "[dim]Generation is lazy and cheapest-first — the Step 5 cascade stops at "
        "the first successful decode, so a good capture pays only for variant 1.[/dim]"
    )
    if out_dir:
        console.print(f"\nWritten to [bold]{out_dir}[/bold]")


@app.command("decode")
def decode_file(
    image_file: Path = typer.Argument(
        ..., help="Card photo to decode", exists=True, dir_okay=False
    ),
    max_variants: int = typer.Option(0, "--max-variants", help="Stop after N variants (0 = all)"),
    budget: float = typer.Option(
        0.0, "--budget", help="Wall-clock budget in seconds (0 = unlimited)"
    ),
    show_payload: bool = typer.Option(
        False, "--show-payload", help="Print the decoded payload (contains personal data)"
    ),
) -> None:
    """Run the full ingest → preprocess → decode pipeline on one image."""
    configure_logging(json_output=False)

    try:
        image = ImageIngestor().ingest(image_file.read_bytes(), filename=image_file.name)
    except IngestError as exc:
        console.print(f"[bold red]REJECTED at ingest[/bold red]  {exc.code.value}")
        console.print(f"employee : {exc.user_message}")
        raise typer.Exit(code=1) from exc

    cascade = QrDecoderCascade(
        max_variants=max_variants or None,
        time_budget_seconds=budget or None,
    )
    started = time.perf_counter()
    result = cascade.decode(PreprocessingVariantGenerator().generate(image))
    elapsed_ms = (time.perf_counter() - started) * 1000

    t = Table(title="Decode", header_style="bold")
    t.add_column("Property")
    t.add_column("Value")
    t.add_row("Image", f"{image.width} x {image.height}")
    t.add_row("Decoders tried", ", ".join(cascade.decoder_names) or "[red]none[/red]")
    t.add_row("Variants consumed", str(result.attempts))
    t.add_row("Elapsed", f"{elapsed_ms:.0f} ms")
    if result.success:
        t.add_row("Winning decoder", result.decoder or "—")
        t.add_row("Winning strategy", result.strategy or "—")
        t.add_row("Payload length", f"{len(result.raw_payload or ''):,} chars")
    console.print(t)

    console.print()
    if result.success:
        console.print("[bold green]✓ Secure QR decoded[/bold green]")
        if show_payload:
            console.print(f"\n[dim]{result.raw_payload}[/dim]")
        else:
            console.print(
                "[dim]Payload withheld — it contains personal data. Use --show-payload "
                "only if you understand where that output will end up.[/dim]"
            )
    else:
        if result.foreign_qr_found:
            console.print(
                "[bold yellow]A QR was found, but it is not an Aadhaar code[/bold yellow]"
            )
            console.print(
                "employee : This does not look like an Aadhaar card. Please "
                "photograph the back of your Aadhaar, where the QR code is."
            )
        else:
            console.print("[bold yellow]No QR code could be read[/bold yellow]")
            console.print(
                "employee : We could not read the QR code. Please photograph the "
                "BACK of your Aadhaar card in good light, holding it flat."
            )
        raise typer.Exit(code=1)


@app.command("decoders")
def list_decoders() -> None:
    """Show which QR decoder backends are usable on this host."""
    t = Table(title="QR decoder backends", header_style="bold")
    t.add_column("Backend")
    t.add_column("Status")
    t.add_column("Note")
    notes = {
        "zxing-cpp": "strongest on dense symbols — first in the cascade",
        "opencv-wechat": "needs opencv-contrib + model files",
        "pyzbar": "needs a system libzbar shared library",
        "opencv": "always present; weakest on dense symbols — last resort",
    }
    for name, ok in decoder_availability().items():
        t.add_row(
            name,
            "[green]available[/green]" if ok else "[dim]unavailable[/dim]",
            notes.get(name, ""),
        )
    console.print(t)
    console.print(
        "\n[dim]Backends are optional by design — a host with only zxing-cpp and "
        "OpenCV still works.[/dim]"
    )


@app.command("verify")
def verify_document(
    front: Path = typer.Argument(
        ..., help="Photo of the FRONT of the Aadhaar card", exists=True, dir_okay=False
    ),
    back: Path = typer.Argument(
        ..., help="Photo of the BACK of the Aadhaar card", exists=True, dir_okay=False
    ),
    cert_dir: Path = typer.Option(
        Path("certs"), "--certs", "-c", help="Directory of UIDAI certificates"
    ),
    strictness: str = typer.Option("STANDARD", "--strictness", help="LENIENT | STANDARD | STRICT"),
    budget: float = typer.Option(12.0, "--budget", help="Wall-clock budget for the document"),
    show_fields: bool = typer.Option(
        False, "--show-fields", help="Print extracted demographics (personal data)"
    ),
) -> None:
    """★ Verify an Aadhaar document from both card faces.

    The full pipeline: ingest → preprocess → decode → parse → verify signature →
    verdict. The Secure QR may be on either side; both are tried.
    """
    configure_logging(json_output=False)

    store = FileCertificateStore(cert_dir) if cert_dir.exists() else None
    certificates: list[UidaiCertificate] = []
    if store is not None:
        try:
            store.load()
            certificates = store.certificates()
        except TrustStoreError as exc:
            console.print(f"[yellow]{exc.message}[/yellow]")

    if not certificates:
        console.print(
            "[bold red]Trust store is empty.[/bold red] Nothing can be verified.\n"
            "[dim]This is correct behaviour — no trust anchor, no approval. "
            "See certs/README.md.[/dim]\n"
        )

    # The privacy filter refuses the placeholder secret — correctly, since a
    # guessable key makes reference hashes brute-forceable. For local CLI use we
    # substitute an obviously-local key and say so, rather than either crashing
    # or quietly pretending the hash is production-grade.
    configured = get_settings().reference_hash_secret
    if not configured or configured.startswith("CHANGE-ME"):
        console.print(
            "[yellow]AVS_REFERENCE_HASH_SECRET is not set.[/yellow] Using a local "
            "development key.\n[dim]Reference hashes from this run are NOT "
            "production-grade and must not be stored. Set the variable from a "
            "vault before deploying.[/dim]\n"
        )
        configured = "local-development-key-not-for-production"

    verifier = DocumentVerifier(
        SecureQrVerifier(certificates),
        DataMinimisingFilter(hash_secret=configured),
        strictness=Strictness(strictness.upper()),
        time_budget_seconds=budget,
    )

    result = verifier.verify(
        [
            SideInput(CardSide.FRONT, front.read_bytes(), front.name),
            SideInput(CardSide.BACK, back.read_bytes(), back.name),
        ]
    )

    st = Table(title="Card sides", header_style="bold")
    st.add_column("Side")
    st.add_column("Accepted", justify="center")
    st.add_column("QR", justify="center")
    st.add_column("Decoder")
    st.add_column("Variants", justify="right")
    st.add_column("ms", justify="right")
    for side in result.sides:
        st.add_row(
            side.side.value,
            "[green]yes[/green]" if side.ingested else "[red]no[/red]",
            "[green]yes[/green]" if side.decoded else "[dim]no[/dim]",
            side.decoder or "—",
            str(side.variants_tried),
            str(side.processing_ms),
        )
    console.print(st)

    ct = Table(title="Checks", header_style="bold")
    ct.add_column("Check")
    ct.add_column("Result")
    ct.add_column("Detail")
    colours = {"PASS": "green", "FAIL": "red", "WARN": "yellow", "SKIP": "dim"}
    for c in result.checks:
        star = "★ " if c.name is CheckName.SIGNATURE_VERIFY else ""
        ct.add_row(
            star + c.name.value,
            f"[{colours[c.result.value]}]{c.result.value}[/{colours[c.result.value]}]",
            c.detail or (c.error.value if c.error else ""),
        )
    console.print(ct)

    if show_fields and result.identity:
        ft = Table(title="Signed fields", header_style="bold")
        ft.add_column("Field")
        ft.add_column("Value")
        ft.add_row("Name", result.identity.name)
        ft.add_row("DOB", result.identity.dob)
        ft.add_row("Gender", result.identity.gender)
        ft.add_row("Aadhaar", f"XXXX XXXX {result.identity.aadhaar_last4}")
        ft.add_row("Reference", result.identity.reference_id)
        ft.add_row("Hash", (result.reference_hash or "")[:40] + "…")
        console.print(ft)

    console.print()
    if result.verdict is Verdict.VERIFIED:
        console.print(
            f"[bold green]✓ {result.verdict.value}[/bold green]  ({result.processing_ms} ms)"
        )
    elif result.verdict.requires_human_review:
        console.print(f"[bold yellow]⚠ {result.verdict.value}[/bold yellow] — routed to HR review")
    else:
        console.print(f"[bold yellow]{result.verdict.value}[/bold yellow] — employee should retry")

    console.print(f"\n[bold]Employee sees:[/bold] {result.user_message}")
    console.print(
        f"\n[dim]auto-approve={result.is_auto_approve} · "
        f"auto-reject={result.verdict.is_auto_reject} (always False) · "
        f"purge after {result.purge_after.isoformat() if result.purge_after else '—'}[/dim]"
    )

    if not result.is_auto_approve:
        raise typer.Exit(code=1)


certs_app = typer.Typer(help="UIDAI certificate trust store.", no_args_is_help=True)
app.add_typer(certs_app, name="certs")


@certs_app.command("status")
def certs_status(
    cert_dir: Path = typer.Option(Path("certs"), "--dir", "-d", help="Certificate directory"),
    warn_days: int = typer.Option(90, "--warn-days", help="Expiry alert threshold"),
    strict: bool = typer.Option(
        False, "--strict", help="Exit non-zero on any warning (use in CI and health checks)"
    ),
) -> None:
    """Show the trust store: certificates, expiry, pinning, and load issues."""
    configure_logging(json_output=False)

    store = FileCertificateStore(cert_dir, warn_days=warn_days)
    try:
        store.load()
    except TrustStoreError as exc:
        console.print(f"[bold red]TRUST STORE ERROR[/bold red]\n{exc.message}")
        raise typer.Exit(code=2) from exc

    health = store.health()
    certificates = store.certificates()

    if certificates:
        t = Table(title=f"Certificates in {cert_dir}/", header_style="bold")
        t.add_column("File")
        t.add_column("Subject")
        t.add_column("Serial")
        t.add_column("Expires")
        t.add_column("Days", justify="right")
        t.add_column("Status")

        for cert in certificates:
            days = cert.days_to_expiry
            if cert.is_expired:
                status, colour = "EXPIRED", "red"
            elif days <= warn_days:
                status, colour = "EXPIRING", "yellow"
            else:
                status, colour = "OK", "green"
            subject = cert.subject if len(cert.subject) <= 40 else cert.subject[:37] + "…"
            t.add_row(
                cert.source,
                subject,
                cert.serial[:16],
                cert.not_valid_after.date().isoformat(),
                str(days),
                f"[{colour}]{status}[/{colour}]",
            )
        console.print(t)
    else:
        console.print(f"[yellow]No certificates found in {cert_dir}/[/yellow]")

    if health.issues:
        issues = Table(title="Load issues", header_style="bold")
        issues.add_column("File")
        issues.add_column("Reason")
        for issue in health.issues:
            marker = "[red]REFUSED[/red] " if issue.fatal else ""
            issues.add_row(issue.filename, marker + issue.reason)
        console.print(issues)

    console.print()
    console.print(
        f"Pinning : {'[green]ON[/green]' if health.pinning_enabled else '[yellow]OFF[/yellow]'}"
    )
    if not health.pinning_enabled:
        console.print(
            f"[dim]  No {PIN_FILE_NAME} present. Anyone who can write to {cert_dir}/ "
            f"could add a certificate and mint approvals. See certs/README.md.[/dim]"
        )

    colour = {"OK": "green", "WARNING": "yellow"}.get(health.status.value, "red")
    console.print(f"Status  : [{colour}]{health.status.value}[/{colour}] — {health.summary()}")

    if not health.is_ready:
        console.print(
            "\n[bold red]✗ Trust store is not usable — no document can be verified.[/bold red]"
        )
        console.print("[dim]This is correct behaviour: no trust anchor, no approval.[/dim]")
        raise typer.Exit(code=2)

    if strict and health.status.is_actionable:
        raise typer.Exit(code=1)


@certs_app.command("fingerprints")
def certs_fingerprints(
    cert_dir: Path = typer.Option(Path("certs"), "--dir", "-d", help="Certificate directory"),
) -> None:
    """Print SHA-256 fingerprints in FINGERPRINTS.txt format.

    Verify each against UIDAI's published value, then save the output to
    certs/FINGERPRINTS.txt to enable pinning.
    """
    store = FileCertificateStore(cert_dir)
    try:
        store.load()
    except TrustStoreError as exc:
        console.print(f"[bold red]{exc.message}[/bold red]")
        raise typer.Exit(code=2) from exc

    console.print("[dim]# SHA-256 fingerprints of trusted UIDAI certificates.[/dim]")
    console.print("[dim]# Verify each against UIDAI's published value before pinning.[/dim]")
    for cert in store.certificates():
        console.print(f"{cert.fingerprint_sha256}  {cert.source}")


@certs_app.command("pin")
def certs_pin(
    cert_dir: Path = typer.Option(Path("certs"), "--dir", "-d", help="Certificate directory"),
    yes: bool = typer.Option(False, "--yes", help="Skip the confirmation prompt."),
) -> None:
    """Write FINGERPRINTS.txt, enabling certificate pinning.

    ⛔ WHY PINNING MATTERS MORE THAN IT SOUNDS

       A certificate in the trust store is a LICENCE TO MINT APPROVALS. Anyone
       who can write a file into `certs/` can add their own certificate, sign
       forged Aadhaar payloads with the matching private key, and this service
       will report VERIFIED — correctly, because the signature really does
       verify against a certificate we chose to trust.

       With FINGERPRINTS.txt present, only certificates whose SHA-256 is listed
       are loaded. A dropped-in certificate is refused, loudly.

    ⚠ Verify each fingerprint against UIDAI's published value BEFORE pinning.
      Pinning a certificate you never verified pins whatever you happened to
      download — including, if you were unlucky, an attacker's.
    """
    store = FileCertificateStore(cert_dir)
    try:
        store.load()
    except TrustStoreError as exc:
        console.print(f"[bold red]{exc.message}[/bold red]")
        raise typer.Exit(code=2) from exc

    certificates = store.certificates()
    if not certificates:
        console.print(f"[red]No certificates in {cert_dir} — nothing to pin.[/red]")
        raise typer.Exit(code=1)

    pin_file = cert_dir / PIN_FILE_NAME
    if pin_file.exists() and not yes:
        console.print(f"[yellow]{pin_file} already exists.[/yellow] Re-run with --yes to replace.")
        raise typer.Exit(code=1)

    table = Table(title="About to pin", header_style="bold")
    table.add_column("File")
    table.add_column("SHA-256")
    table.add_column("Expires")
    for cert in certificates:
        table.add_row(cert.source, cert.fingerprint_sha256, str(cert.not_valid_after.date()))
    console.print(table)

    console.print(
        "\n[bold yellow]Check every fingerprint above against UIDAI's published "
        "value.[/bold yellow]\n[dim]Pinning an unverified certificate pins whatever you "
        "downloaded.[/dim]"
    )
    if not yes and not typer.confirm("\nAll fingerprints verified against UIDAI?"):
        console.print("Nothing written.")
        raise typer.Exit(code=1)

    lines = [
        "# SHA-256 fingerprints of trusted UIDAI certificates.",
        "# Only certificates listed here are loaded. See certs/README.md.",
        f"# Written by `avs certs pin` on {time.strftime('%Y-%m-%d')}.",
        "",
    ]
    lines += [f"{c.fingerprint_sha256}  {c.source}" for c in certificates]
    pin_file.write_text("\n".join(lines) + "\n", encoding="utf-8")

    console.print(f"\n[green]Pinned {len(certificates)} certificate(s) → {pin_file}[/green]")
    console.print("[dim]Run `avs certs status` to confirm pinning is ON.[/dim]")


@app.command("serve")
def serve(
    host: str = typer.Option("127.0.0.1", help="Bind address."),
    port: int = typer.Option(8000, help="Bind port."),
    certs: Path = typer.Option(Path("certs"), help="UIDAI certificate directory."),
    workers: int = typer.Option(2, help="Concurrent verifications."),
    queue: str = typer.Option(
        "in-process",
        help="Job queue backend. 'in-process' LOSES QUEUED JOBS ON RESTART — "
        "correct for a single instance, wrong for a cluster.",
    ),
    max_queued: int = typer.Option(32, help="Queue capacity before 503."),
    budget: float = typer.Option(12.0, help="Seconds allowed per document."),
    strictness: str = typer.Option("standard", help="lenient | standard | strict."),
    hash_secret: str = typer.Option(
        "", envvar="AVS_HASH_SECRET", help="HMAC key for reference-id hashing."
    ),
    callback_secret: str = typer.Option(
        "", envvar="AVS_CALLBACK_SECRET", help="HMAC key for signing callbacks."
    ),
    audit: Path = typer.Option(
        Path("audit.jsonl"),
        help="Hash-chained audit trail. Verify with `avs audit verify`.",
    ),
    tenants: Path = typer.Option(
        Path("tenants.json"), help="Tenant registry. Secrets come from the environment."
    ),
    no_auth: bool = typer.Option(
        False, "--no-auth", help="DEV ONLY. Disable HMAC authentication entirely."
    ),
    allow_private_urls: bool = typer.Option(
        False,
        "--allow-private-urls",
        help="DEV ONLY. Permits fetching from localhost/private ranges.",
    ),
    reload: bool = typer.Option(False, "--reload", help="Auto-reload on code change."),
) -> None:
    """Run the HTTP API.

    Binds to localhost by default. Put a TLS-terminating reverse proxy in front
    before exposing it — this service has no authentication of its own yet
    (Step 9), so anything that can reach the port can submit documents.
    """
    # Preflight. Both of these fail deep inside FastAPI/uvicorn with a traceback
    # that buries the one line that matters, so check here and say it plainly.
    missing: list[str] = []
    try:
        import uvicorn
    except ImportError:
        uvicorn = None  # type: ignore[assignment]
        missing.append("uvicorn")
    try:
        import multipart  # noqa: F401
    except ImportError:
        # FastAPI raises at ROUTE-REGISTRATION time, not on first request — the
        # whole app fails to build, so this is fatal rather than degraded.
        missing.append("python-multipart")

    if missing:
        console.print(f"[bold red]Missing dependency:[/bold red] {', '.join(missing)}")
        console.print("\nInstall the service extra:")
        console.print(r'  [cyan]pip install -e ".\[service]"[/cyan]')
        console.print("\n[dim]Or just the missing packages:[/dim]")
        console.print(f"  [cyan]pip install {' '.join(missing)}[/cyan]")
        raise typer.Exit(code=1)

    from avs.api import create_app
    from avs.security import FileTenantRegistry, TenantRegistryError

    registry = None
    if not no_auth:
        try:
            registry = FileTenantRegistry(tenants)
            registry.load()
        except TenantRegistryError as exc:
            console.print(f"[bold red]Tenant registry unusable:[/bold red] {exc.message}")
            console.print(
                "\n[dim]Every /v1 route requires an HMAC signature from a known tenant.\n"
                "Create the registry (see docs), or use [/dim][cyan]--no-auth[/cyan]"
                "[dim] for local development.[/dim]"
            )
            raise typer.Exit(code=1) from exc
        console.print(f"[dim]Authentication: {len(registry.tenant_ids)} tenant(s) loaded.[/dim]")
    else:
        # ⛔ Loud, not a footnote. A service left running with this flag accepts
        #   a verification request from anyone who can reach the port.
        console.print(
            "[bold red]⚠  AUTHENTICATION IS DISABLED (--no-auth).[/bold red] Every caller "
            "is accepted\n   as 'anonymous'. Development only — never expose this port."
        )

    if allow_private_urls:
        console.print(
            "[bold yellow]⚠  --allow-private-urls is set.[/bold yellow] The SSRF guard "
            "will permit\n   loopback and private addresses. Development only — never "
            "in production."
        )
    if not hash_secret:
        console.print(
            "[yellow]⚠  No AVS_HASH_SECRET set.[/yellow] Using a development key; "
            "reference-id\n   hashes will not be stable across deployments."
        )

    cert_count = (
        len(list(certs.glob("*.pem"))) + len(list(certs.glob("*.cer"))) if certs.is_dir() else 0
    )
    if cert_count == 0:
        console.print(
            f"[bold red]⚠  No certificates in {certs}.[/bold red] The service will start "
            "but\n   [bold]/ready will report 503[/bold] and every document will return "
            "ERROR."
        )

    if queue != "in-process":
        console.print(
            f"[bold red]Unknown queue backend {queue!r}.[/bold red] Only 'in-process' exists "
            "today;\n   a durable backend implements the same JobQueue Protocol."
        )
        raise typer.Exit(code=1)

    if host not in {"127.0.0.1", "localhost", "::1"}:
        # In-process queueing plus a non-local bind means a restart silently
        # drops work that a real caller is polling for.
        console.print(
            "[yellow]⚠  Binding beyond localhost with the in-process queue.[/yellow] Queued "
            "jobs are\n   lost on restart, and nothing tells the caller. Fine for a single "
            "instance;\n   a cluster needs a durable backend."
        )

    console.print(f"\n[bold]Aadhaar Verification Service[/bold] → http://{host}:{port}")
    console.print(f"[dim]docs http://{host}:{port}/docs   ready http://{host}:{port}/ready[/dim]\n")

    application = create_app(
        cert_dir=str(certs),
        hash_secret=hash_secret,
        strictness=Strictness(strictness.upper()),
        workers=workers,
        max_queued=max_queued,
        time_budget_seconds=budget,
        allow_private_urls=allow_private_urls,
        callback_secret=callback_secret,
        audit_path=str(audit),
        tenants=registry,
        require_auth=not no_auth,
    )
    uvicorn.run(application, host=host, port=port, reload=reload, log_config=None)


@app.command("classify")
def classify_command(
    target: list[Path] = typer.Argument(..., help="An image file, or a FOLDER of images"),
    model_dir: Path = typer.Option(Path("models"), "--models", help="Model directory"),
) -> None:
    """Classify an image — or every image in a folder — and show the features.

    ⚠ ADVISORY ONLY. This cannot verify anything and cannot reject anything. It
      answers "does this look like a document?" so that a failed verification
      can say something true instead of "retake it in better light".

    UNKNOWN is a normal, common answer. The heuristic backend claims exactly one
    thing — that an image contains no document at all — and says UNKNOWN to
    every other question, because it has no trained model behind it.

    ⛔ ACCEPTS A FOLDER ON PURPOSE.

       This originally demanded one file path. Documenting it meant writing a
       placeholder filename, and a pasted placeholder is not a path — PowerShell
       split `<pick any file>` on its spaces and typer reported "unexpected extra
       argument", which tells the user nothing about what went wrong.

       Pointing at a folder needs no filename, so there is nothing to guess and
       nothing to paste wrongly. `list[Path]` also means a shell glob that
       expands to many paths still works instead of erroring.
    """
    configure_logging(json_output=False)

    import numpy as np

    from avs.ai.classify import build_classifier
    from avs.ai.classify.features import extract_features

    # ⛔ A leftover placeholder is the most likely bad input, so name it rather
    #    than emitting a generic "no such file". An error that does not say what
    #    to do next is only marginally better than no error.
    for candidate in target:
        text = str(candidate)
        if any(character in text for character in "<>*?") and not candidate.exists():
            console.print(
                f"[bold red]That looks like a placeholder, not a path:[/bold red] {text}\n\n"
                "Point at the FOLDER instead — no filename needed:\n"
                r"    python -m avs.cli classify C:\aadhaar-corpus\phone-a-dim"
            )
            raise typer.Exit(code=2)

    images: list[Path] = []
    for candidate in target:
        if candidate.is_dir():
            images.extend(sorted(p for p in candidate.rglob("*") if p.is_file()))
        elif candidate.is_file():
            images.append(candidate)
        else:
            console.print(f"[bold red]No such file or folder:[/bold red] {candidate}")
            raise typer.Exit(code=2)

    if not images:
        console.print(f"[yellow]No files found in {target[0]}.[/yellow]")
        raise typer.Exit(code=1)

    # ⛔ Opts INTO the retired heuristic deliberately. `build_classifier()`
    #    defaults to False because the heuristic caught 0 of 19 real
    #    wrong-uploads, but this command is a diagnostic — its whole job is to
    #    show what the features measure, which is exactly how that was found.
    classifier = build_classifier(str(model_dir), allow_heuristic=True)
    if classifier is None:
        console.print("[yellow]No classifier available.[/yellow]")
        raise typer.Exit(code=1)

    from avs.ai.classify import HeuristicClassifier

    if isinstance(classifier, HeuristicClassifier):
        console.print(
            "[dim]Backend: heuristic (RETIRED from production — caught 0 of 19 real\n"
            "wrong-uploads). Shown here for diagnostics only.[/dim]"
        )

    import cv2

    decoded_any = False
    for path in images:
        decoded = cv2.imdecode(np.fromfile(path, dtype=np.uint8), cv2.IMREAD_COLOR)
        if decoded is None:
            # Not an image. Skipped silently when scanning a folder — corpus
            # directories routinely hold stray notes and thumbnails.
            if len(images) == 1:
                console.print(f"[bold red]Could not decode:[/bold red] {path}")
                raise typer.Exit(code=2)
            continue

        decoded_any = True
        features = extract_features(decoded)
        prediction = classifier.classify_features(features)  # type: ignore[union-attr]
        _print_classification(path, features, prediction, single=len(images) == 1)

    if not decoded_any:
        console.print("[yellow]None of those files could be decoded as images.[/yellow]")
        raise typer.Exit(code=1)


def _print_classification(path: Path, features, prediction, *, single: bool) -> None:
    colour = {"not_a_document": "yellow", "unknown": "dim"}.get(prediction.doc_type.value, "green")

    console.print(
        f"\n[bold]{path.name}[/bold]  ->  [bold {colour}]{prediction.doc_type.value}"
        f"[/bold {colour}] (confidence {prediction.confidence:.2f}, "
        f"backend {prediction.model_version})"
    )

    row = features.as_row()
    if single:
        table = Table(header_style="bold", title="Measured features")
        table.add_column("Feature")
        table.add_column("Value", justify="right")
        for key, value in row.items():
            table.add_row(key, f"{value:.4f}" if isinstance(value, float) else str(value))
        console.print(table)
    else:
        # ★ The three numbers that decide the answer. Printing all ten per image
        #   across a folder buries them.
        console.print(
            f"    [dim]edge={row['edge_density']:.4f}  "
            f"brightness={row['mean_brightness']:.1f}  "
            f"qr={'yes' if row['has_qr'] else 'no'}  "
            f"quad={'yes' if row['has_document_quad'] else 'no'}[/dim]"
        )

    if single and prediction.doc_type.value == "unknown":
        console.print(
            "\n[dim]UNKNOWN changes nothing — the deterministic message stands. "
            "Without a trained model this is the expected answer for anything "
            "that is not obviously empty.[/dim]"
        )


models_app = typer.Typer(help="AI model registry (Step 12).", no_args_is_help=True)
app.add_typer(models_app, name="models")


@models_app.command("status")
def models_status(
    model_dir: Path = typer.Option(Path("models"), "--dir", "-d", help="Model directory"),
) -> None:
    """Show declared models, their pinned digests, and any that cannot be used.

    ⚠ An empty registry is a HEALTHY state, not a warning. Every AI capability
      is optional and the deterministic pipeline is complete without any of
      them — see CONTRACTS.md §6. This command exits 0 with no models declared.
    """
    configure_logging(json_output=False)

    from avs.ai.modelmgr import RegistryError, load_registry, onnxruntime_available

    try:
        registry = load_registry(model_dir)
    except RegistryError as exc:
        console.print(f"[bold red]MODEL REGISTRY ERROR[/bold red]\n{exc.message}")
        raise typer.Exit(code=2) from exc

    runtime_ok = onnxruntime_available()
    console.print(
        "onnxruntime: "
        + ("[green]installed[/green]" if runtime_ok else "[yellow]not installed[/yellow]")
    )

    if not registry.names:
        console.print(
            f"\n[dim]No models declared in {model_dir}. "
            f"This is normal — the deterministic pipeline runs without them.[/dim]"
        )
        return

    table = Table(header_style="bold")
    table.add_column("Model")
    table.add_column("Version")
    table.add_column("State")
    table.add_column("Digest", overflow="fold")

    problems = 0
    for name in registry.names:
        spec = registry.get(name)
        if spec is None:
            table.add_row(name, "—", "[dim]disabled[/dim]", "—")
            continue
        # Calling path_for is what performs the digest check.
        usable = registry.path_for(name) is not None
        if usable:
            state = "[green]pinned ✓[/green]"
        else:
            state = "[bold red]UNUSABLE[/bold red]"
            problems += 1
        table.add_row(name, spec.version, state, spec.sha256[:16] + "…")

    console.print(table)

    for name, reason in registry.problems.items():
        console.print(f"[red]{name}:[/red] {reason}")

    if problems:
        # ⛔ Non-zero, but the SERVICE still runs. This tells an operator that a
        #    capability is missing; it does not mean verification is broken.
        console.print(
            "\n[dim]Verification still works. These models are accelerators, "
            "not requirements.[/dim]"
        )
        raise typer.Exit(code=1)


@models_app.command("pin")
def models_pin(
    model_dir: Path = typer.Option(Path("models"), "--dir", "-d", help="Model directory"),
) -> None:
    """Print the SHA-256 of every .onnx file, ready to paste into models.json.

    ⛔ Only run this on files you obtained deliberately. Pinning re-reads
       whatever is on disk, so pinning a file someone else placed there records
       their model as the expected one — which defeats the check entirely. This
       is the same hazard as `certs pin`.
    """
    import hashlib

    files = sorted(Path(model_dir).glob("*.onnx"))
    if not files:
        console.print(f"[yellow]No .onnx files in {model_dir}.[/yellow]")
        return

    #: SHA-256 of zero bytes. Pinning this means pinning an empty file — the
    #: digest is perfectly valid and every later check passes, which is exactly
    #: what makes it dangerous.
    empty_digest = hashlib.sha256(b"").hexdigest()

    entries: list[dict[str, str]] = []
    rejected = 0

    for path in files:
        digest = hashlib.sha256()
        with path.open("rb") as handle:
            while chunk := handle.read(1024 * 1024):
                digest.update(chunk)
        hexdigest = digest.hexdigest()
        size = path.stat().st_size

        # ⛔ Refuse to pin something that cannot be a model.
        #
        #    A digest over garbage is still a VALID digest: `models status` would
        #    show "pinned ✓" and the operator would reasonably believe the model
        #    was verified. Pinning is meant to answer "is this the file we
        #    chose?" — it says nothing about whether the file is a model at all,
        #    so that gap has to be closed here, at the only point a human looks.
        if hexdigest == empty_digest or size == 0:
            console.print(f"[bold red]✗ {path.name} is EMPTY — refusing to pin.[/bold red]")
            rejected += 1
            continue

        if size < 1024:
            # Real ONNX graphs are kilobytes at minimum; the smallest model this
            # project will ship is a few hundred KB.
            console.print(
                f"[yellow]⚠ {path.name} is only {size} bytes — too small to be a "
                f"real model. Pinning it anyway, but check it.[/yellow]"
            )

        entries.append(
            {
                "name": path.stem,
                "version": "1.0.0",
                "filename": path.name,
                "sha256": hexdigest,
            }
        )

    if not entries:
        console.print(f"[yellow]Nothing to pin ({rejected} file(s) rejected).[/yellow]")
        raise typer.Exit(code=1)

    console.print(json.dumps({"models": entries}, indent=2))
    console.print(
        f"\n[dim]Review the names and versions, then save as "
        f"{Path(model_dir) / 'models.json'}.[/dim]"
    )


audit_app = typer.Typer(help="Hash-chained audit trail.", no_args_is_help=True)
app.add_typer(audit_app, name="audit")


@audit_app.command("verify")
def audit_verify(
    path: Path = typer.Argument(Path("audit.jsonl"), help="Trail to check."),
) -> None:
    """Check every link in the chain.

    ⛔ Run this before answering any dispute about a verdict. An intact chain
       means the record you are reading is the record that was written.

    Detects content edits, deletions, insertions and reordering. It cannot
    detect a wholesale rewrite by someone with write access — that needs an
    append-only store, and the `AuditSink` Protocol exists so one can be added.
    """
    from avs.audit import verify_chain

    breaks = verify_chain(path)
    if not breaks:
        from avs.audit import FileAuditTrail

        count = len(FileAuditTrail(path).entries())
        console.print(f"[bold green]✓ Chain intact.[/bold green] {count} entries in {path}.")
        return

    console.print(f"[bold red]✗ AUDIT TRAIL COMPROMISED — {len(breaks)} problem(s).[/bold red]\n")
    table = Table(header_style="bold red")
    table.add_column("Line", justify="right")
    table.add_column("Job")
    table.add_column("Problem")
    for issue in breaks:
        table.add_row(str(issue.line), issue.job_id or "—", issue.reason)
    console.print(table)
    console.print(
        "\n[dim]Treat every verdict in this file as unproven until the cause is established.[/dim]"
    )
    raise typer.Exit(code=1)


@app.command()
def selftest() -> None:
    """Prove the cryptographic core works — no real Aadhaar needed.

    Generates a throwaway RSA-2048 keypair, builds a synthetic Secure QR, then
    tampers with it. The genuine payload must verify; the tampered one must not.

    This is the demo to run in front of a security team.
    """
    from cryptography.hazmat.primitives import hashes as _hashes
    from cryptography.hazmat.primitives.asymmetric import padding as _padding
    from cryptography.hazmat.primitives.asymmetric import rsa as _rsa

    configure_logging(json_output=False)
    console.print("[dim]Generating throwaway RSA-2048 keypair…[/dim]")

    key = _rsa.generate_private_key(public_exponent=65537, key_size=2048)
    from datetime import datetime, timedelta, timezone

    now = datetime.now(timezone.utc)
    cert = UidaiCertificate(
        serial="selftest",
        subject="CN=AVS Selftest Key",
        public_key=key.public_key(),
        not_valid_before=now - timedelta(days=1),
        not_valid_after=now + timedelta(days=1),
        source="selftest",
    )

    import gzip as _gzip

    fields = [
        "V2",
        "3",
        "1234202608131030000",
        "Test Person",
        "01-01-1990",
        "M",
        "S/O Test Parent",
        "Jaipur",
        "Near Test Park",
        "12-A",
        "Test Colony",
        "302001",
        "Test PO",
        "Rajasthan",
        "Test Marg",
        "Test Tehsil",
        "Jaipur",
    ]
    photo = b"\x00\x00\x00\x0cjP  \r\n\x87\n" + bytes(range(256)) * 2
    body = b"\xff".join(f.encode() for f in fields) + b"\xff" + photo + b"\xa0" * 64

    def encode(data: bytes) -> str:
        return str(int.from_bytes(_gzip.compress(data, mtime=0), "big"))

    signature = key.sign(body, _padding.PKCS1v15(), _hashes.SHA256())
    genuine = encode(body + signature)

    forged_fields = list(fields)
    forged_fields[3] = "Fraud Person"  # one field edited, signature reused
    forged_body = b"\xff".join(f.encode() for f in forged_fields) + b"\xff" + photo + b"\xa0" * 64
    tampered = encode(forged_body + signature)

    parser = SecureQrParser()
    verifier = SecureQrVerifier([cert])

    results = Table(title="Self-test", header_style="bold")
    results.add_column("Case")
    results.add_column("Expected")
    results.add_column("Actual")
    results.add_column("", justify="center")

    ok = True
    for label, qr, expected in [
        ("Genuine payload", genuine, True),
        ("Name changed, signature reused", tampered, False),
    ]:
        actual = verifier.verify(parser.parse(qr)).valid
        passed = actual is expected
        ok = ok and passed
        results.add_row(
            label,
            "VALID" if expected else "INVALID",
            "VALID" if actual else "INVALID",
            "[green]✓[/green]" if passed else "[red]✗[/red]",
        )
    console.print(results)

    console.print()
    if ok:
        console.print("[bold green]✓ Cryptographic core is working correctly.[/bold green]")
        console.print(
            "[dim]A single edited field invalidated the signature. Forging an "
            "approval would require UIDAI's private key.[/dim]"
        )
    else:
        console.print("[bold red]✗ SELF-TEST FAILED — do not deploy.[/bold red]")
        raise typer.Exit(code=1)


if __name__ == "__main__":
    app()
