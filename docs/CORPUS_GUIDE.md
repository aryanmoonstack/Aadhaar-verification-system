# Corpus shooting guide

What to photograph for each folder in `C:\aadhaar-corpus\`, and which folders
are already finished.

**The single rule that matters:** the card must fill **at least half the frame
width**. Derived from card geometry, not opinion — an Aadhaar is 85.6mm wide and
its Secure QR is ~25mm. At a third of the frame the code lands at 4.0 pixels per
module, and nothing below 4.71 has ever decoded.

| How you framed it | pixels per module | Result |
|---|---|---|
| Card fills the frame | 12.0 | ✅ |
| Card = 70% of width | 8.4 | ✅ |
| Card = half the width | 6.0 | ✅ |
| Card = a third of width | 4.0 | ❌ fails |

---

## Folder status

### ✅ Finished — do not touch

| Folder | n | Why it stays as-is |
|---|---|---|
| `not-document\` | 19 | Perfect. Screenshots, keyboards, faces, sunset — exactly the realistic wrong-uploads needed. Nothing to add. |
| `phone-a-dim\` | 4 | **Deliberately bad, and valuable.** Sharpness 11–32. This is the "too dark / camera shake" failure case, and the quality model must learn to recognise it. Reshooting would destroy the test. |
| `phone-b-angled\` | 6 | **Deliberately bad.** Perspective + distance. Keep. |
| `phone-b-glare\` | 4 | **Deliberately bad.** The hardest case — px/module 13–23 (plenty big) yet 0/4 decode, because glare wipes out modules. Keep. |
| `phone-a-good-light\` | 4 | Best folder — 3/4 decoded. Fine as-is. |

⚠ **The "bad" folders are the test suite.** They are not mistakes to be fixed.
Every one of them is a failure mode the model has to detect, and they cannot be
replaced once deleted.

---

### ⛔ Needs fixing — 2 folders

#### `phone-b-good-light\` — mislabelled

| | px/module | sharpness | decoded |
|---|---|---|---|
| image 1 | 4.42 | 41 | ❌ |
| image 2 | 3.91 | 157 | ❌ |

The name says "good light" but both are below the distance floor (4.71) *and*
the sharpness floor (369). These are not good captures — they were shot too far
back and slightly soft. A folder that claims to hold good examples and holds bad
ones will mislead every future analysis.

**Do:** delete the 2 images, reshoot 4 following the checklist below.

#### `scanner\` — duplicates, not scans

Its 2 images have metrics identical to `phone-a-good-light` ones — `(30.16,
1638)` and `(28.26, 741)`. They are copies. They inflate the corpus size by 10%
while adding no information.

**Do:** delete both. Either produce genuine flatbed scans at 300 DPI, or drop
the folder entirely — phone captures are what the product actually receives.

---

### ➕ Create — `guided\`

This is the important one, and the corpus has nothing like it.

Every existing document photo was taken with **no guidance**. That is why the
decode rate is 23%. This folder answers the open question: *what happens when
someone is told how to hold the camera?*

**Shoot 10–12 photos** — both phones, following the checklist exactly.

---

## The checklist

For `guided\` (and the `phone-b-good-light\` reshoot):

1. **Fill the frame with the card.** Long edge of the card along the long edge
   of the photo, edges nearly touching the sides. This is the one that matters
   most — it fixes 29% of the current failures on its own.
2. **The QR side up.** Whichever face carries the Secure QR.
3. **Card flat on a plain surface.** Not held in the hand — hands tilt, and
   tilt costs sharpness.
4. **Bright, indirect light.** A window works. **Not** direct sunlight and not
   overhead spotlight, both of which cause the glare that kills
   `phone-b-glare`.
5. **Tap to focus on the QR**, wait for the confirmation, then shoot.
6. **Steady.** Elbows on the table, or rest the phone on a book. Sharpness is
   the strongest predictor in the whole dataset — 76% of failures are soft.
7. **Highest resolution the camera offers.** Check settings; many phones default
   to a lower mode.

### What to avoid

- Standing back "to get it all in" — this is the single most common cause
- Shooting in a dim room and letting the phone slow the shutter
- A lamp directly above the card
- Any zoom (digital zoom throws away the resolution you need)

---

## When done

```powershell
python scripts\measure_decode_quality.py C:\aadhaar-corpus --out quality.csv
```

Read the `DECODE RATE` and the per-folder table.

**Prediction on record:** `guided\` should decode **above 80%**, versus 23% for
the unguided folders. If it does not, the model of this problem is wrong and
that needs finding out before Steps 14–19 are built on top of it.

Re-analysis afterwards is free — no need to re-decode:

```powershell
python scripts\measure_decode_quality.py x --from-csv quality.csv
```

---

## Summary

| Action | Folder | Effort |
|---|---|---|
| Nothing | `not-document`, `phone-a-dim`, `phone-b-angled`, `phone-b-glare`, `phone-a-good-light` | — |
| Delete 2, reshoot 4 | `phone-b-good-light` | 5 min |
| Delete both, or drop the folder | `scanner` | 1 min |
| **Create, shoot 10–12** | **`guided`** | **10 min** |

Total: about fifteen minutes, and it settles whether the 23% is a capture
problem or something deeper.
