# vulnerable-js-repo

The deliberately insecure JavaScript target crossfire's Jazzer.js adapter runs
against. Every bug in here is seeded on purpose and every one of them is known
to the test suite.

## What is seeded

| Detector | Finding | Where |
| --- | --- | --- |
| Jazzer.js (fuzz) | `rangeerror`, reading past a frame that declared more payload than it carries | `src/decode-frame.js` |

The frame header carries a payload length. The decoder trusts it, so a frame
claiming 200 bytes of payload while carrying 4 reads its checksum from past the
end of what it actually has, which is a `RangeError` in JavaScript rather than
the silent overread the same bug is in C.

## Preparing the harness

```sh
./build.sh
```

crossfire spawns `node_modules/.bin/jazzer` from inside the target, so the
target's own install is what makes its harness runnable. There is no compile
step: `build.sh` is `npm install`.

## The two harnesses

```
fuzz/decode-frame.fuzz.js         the decoder as it stands
fuzz/decode-frame-fixed.fuzz.js   the same decoder behind the bounds check
```

Both call one decoder from one source, and the patched behaviour is a flag on
it, the way the C fixture is compiled with `-DPARSE_REQUEST_FIXED`. The fixed
harness is what "a fixed harness yields nothing within budget" means in the
detection tests.

## Running the target's tests

```sh
./test.sh
```

Well formed frames only, so it passes against both. It is the regression
baseline for the test gate, not a bug finder.
