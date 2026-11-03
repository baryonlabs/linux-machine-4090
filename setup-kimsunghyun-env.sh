#!/usr/bin/env bash
# Hand over the prepared research environment to student account student1.
# Run ONCE on martin-B650M-K as admin (detached, survives SSH drop):
#   sudo systemd-run --unit=envsetup bash /home/martin/setup-student1-env.sh
#   journalctl -u envsetup -f          # follow progress (build takes ~20-40 min)
# Idempotent: safe to re-run (sudo systemctl reset-failed envsetup first if the unit name is taken).
set -uo pipefail
export LC_ALL=C

U=student1
UH=/home/$U
UD=/mnt/data/users/$U                     # == $UH/data (symlink)
STAGE=/mnt/data/users/admin2/stage-student1
BUILD_SRC=/home/martin/build-envs.sh
[ -f "$BUILD_SRC" ] || BUILD_SRC=$STAGE/build-envs.sh

declare -a RESULTS=()
FAILED=0
res(){ RESULTS+=("$1  $2"); [ "$1" = FAIL ] && FAILED=1; echo ">>> $1: $2"; }
hdr(){ echo; echo "================ $* ($(date '+%F %T'))"; }

# ------------------------------------------------------------------ 0. preflight
hdr "0. preflight"
[ "$(id -u)" = 0 ] || { echo "must run as root (sudo)"; exit 1; }
id "$U" >/dev/null 2>&1 || { echo "user $U missing"; exit 1; }
[ -d "$UD" ] || install -d -m 700 -o "$U" -g "$U" "$UD"
[ -L "$UH/data" ] || { ln -sfn "$UD" "$UH/data"; chown -h "$U:$U" "$UH/data"; }
[ -f "$BUILD_SRC" ] || { echo "build-envs.sh not found"; exit 1; }
command -v uv >/dev/null || { echo "uv not in PATH"; exit 1; }
ls -ld "$UH" "$UH/data" "$UD"

# ------------------------------------------------------------------ 1. HF cache (mv, same filesystem)
hdr "1. HF model cache -> $UD/hf-cache"
install -d -o "$U" -g "$U" -m 700 "$UD/hf-cache"
# huggingface_hub>=1.x keeps file contents in a shared hub/blobs/ store and models--*/blobs/* are
# relative symlinks into it -> move the whole hub/ directory, never individual models--* dirs.
if [ -d "$STAGE/hf-cache/hub" ]; then
  find "$STAGE/hf-cache/hub" -name '*.incomplete' -delete 2>/dev/null || true
  if [ ! -e "$UD/hf-cache/hub" ] || [ -z "$(ls -A "$UD/hf-cache/hub" 2>/dev/null)" ]; then
    rmdir "$UD/hf-cache/hub" 2>/dev/null || true
    mv "$STAGE/hf-cache/hub" "$UD/hf-cache/hub" && echo "moved hub/ -> $UD/hf-cache/hub"
  else
    echo "WARNING: $UD/hf-cache/hub already populated; leaving $STAGE/hf-cache/hub in place (not merged)"
  fi
else
  echo "staging hub/ already moved (re-run)"
fi
# never hand over any credentials
find "$UD/hf-cache" \( -name token -o -name stored_tokens -o -name '*.token' \) -print -delete 2>/dev/null || true
chown -R "$U:$U" "$UD/hf-cache"; chmod -R u+rwX,go-rwx "$UD/hf-cache"
install -d -o "$U" -g "$U" -m 700 "$UD/.cache" "$UD/.cache/uv" "$UD/.cache/pip" "$UD/.cache/torch" "$UD/ckpt" "$UD/datasets"
TOK=$(find "$UD/hf-cache" \( -name token -o -name stored_tokens \) 2>/dev/null | head -1 || true)
NMOD=0
for m in models--Qwen--Qwen3-VL-8B-Instruct models--ziHoHe--VidLaDA-8B models--google--siglip2-so400m-patch14-384 models--GSAI-ML--LLaDA-V; do
  ls "$UD/hf-cache/hub/$m/snapshots/"*/config.json >/dev/null 2>&1 && NMOD=$((NMOD+1)) || echo "missing model: $m"
done
BROKEN=$(find "$UD/hf-cache/hub" -xtype l 2>/dev/null | wc -l)
du -sh "$UD/hf-cache/hub" 2>/dev/null || true
if [ -z "$TOK" ] && [ "$NMOD" = 4 ] && [ "$BROKEN" = 0 ]; then res PASS "HF cache: 4/4 repos, 0 broken links, no token"
else res FAIL "HF cache: $NMOD/4 repos, $BROKEN broken links, token='$TOK'"; fi

# ------------------------------------------------------------------ 2. code
hdr "2. code -> $UH/code"
install -d -o "$U" -g "$U" -m 755 "$UH/code"
if [ -d "$STAGE/code/examples" ]; then
  install -d "$UH/code/examples"; cp -rT "$STAGE/code/examples" "$UH/code/examples"
fi
if [ ! -d "$UH/code/VidLaDA/.git" ] && [ -d "$STAGE/code/VidLaDA/.git" ]; then
  cp -a "$STAGE/code/VidLaDA" "$UH/code/VidLaDA"
  find "$UH/code/VidLaDA" \( -name '*.egg-info' -o -name __pycache__ \) -prune -exec rm -rf {} + 2>/dev/null || true
fi   # otherwise build-envs.sh clones it as the student
cp "$BUILD_SRC" "$UH/code/build-envs.sh"
chown -R "$U:$U" "$UH/code"
[ -f "$UH/code/examples/qwen3vl_infer_4bit.py" ] && res PASS "code/examples copied" || res FAIL "code/examples missing"

# ------------------------------------------------------------------ 3. build venvs as the student
hdr "3. build venvs as $U (~/venvs)"
sudo -u "$U" -H bash -s <<'T'
set -euo pipefail
export LC_ALL=C
unset HUGGINGFACE_HUB_CACHE HF_TOKEN
export UV_CACHE_DIR=$HOME/data/.cache/uv XDG_CACHE_HOME=$HOME/data/.cache PIP_CACHE_DIR=$HOME/data/.cache/pip
cd ~
bash ~/code/build-envs.sh ~/venvs ~/code
T
rc=$?
[ $rc = 0 ] && res PASS "venvs qwen3vl + vidlada built and verified (imports, CUDA bf16 matmul, bnb nf4)" || res FAIL "build-envs.sh exit $rc (see log above)"

# ------------------------------------------------------------------ 4. ~/.bashrc block
hdr "4. ~/.bashrc"
RC=$UH/.bashrc
[ -f "$RC" ] || { install -o "$U" -g "$U" -m 644 /dev/null "$RC"; }
sed -i '/^# >>> research-env (managed by admin) >>>$/,/^# <<< research-env <<<$/d' "$RC"
cat >> "$RC" <<'B'
# >>> research-env (managed by admin) >>>
export HF_HOME="$HOME/data/hf-cache"
export HF_HUB_CACHE="$HF_HOME/hub"
export HF_HUB_ENABLE_HF_TRANSFER=1
export HF_XET_HIGH_PERFORMANCE=1
export FORCE_QWENVL_VIDEO_READER=decord   # torchvision>=0.25 has no io.read_video
export XDG_CACHE_HOME="$HOME/data/.cache"
export UV_CACHE_DIR="$HOME/data/.cache/uv"
export PIP_CACHE_DIR="$HOME/data/.cache/pip"
export TORCH_HOME="$HOME/data/.cache/torch"
export TRITON_CACHE_DIR="$HOME/data/.cache/triton"
alias qwen3vl='source ~/venvs/qwen3vl/bin/activate'
alias vidlada='source ~/venvs/vidlada/bin/activate'
alias gpu='watch -n1 nvidia-smi'
# <<< research-env <<<
B
chown "$U:$U" "$RC"
N=$(grep -c '^# >>> research-env (managed by admin) >>>$' "$RC" || true)
[ "$N" = 1 ] && res PASS ".bashrc block (1 copy)" || res FAIL ".bashrc block count=$N"

# ------------------------------------------------------------------ 5. README
hdr "5. README"
cat > "$UH/README.md" <<'R'
# Research environment (video multi-target captioning)

Machine: 1x RTX 4090 24 GB, 30 GB RAM, Ubuntu 24.04. Shared with other users.

## Storage layout
| Path | What goes there |
|---|---|
| `~/code` | your code (git repos). `~/code/VidLaDA` = upstream VidLaDA repo, `~/code/examples` = smoke tests |
| `~/venvs` | Python environments (do not move them: venvs contain absolute paths) |
| `~/data` (= `/mnt/data/users/student1`, 4.9 TB disk) | datasets, checkpoints, caches. Put **everything large** here |
| `~/data/hf-cache` | Hugging Face cache (`HF_HOME`). Models are already downloaded |
| `~/data/ckpt`, `~/data/datasets` | suggested places for checkpoints and data |
| `~/data/.cache` | uv / pip / torch / triton caches |

Home (`/home`) is on a smaller shared disk: keep it for code and envs only.

## Environments
| alias | venv | Python | Main packages |
|---|---|---|---|
| `qwen3vl` | `~/venvs/qwen3vl` | 3.12 | recent torch, transformers>=4.57, peft, bitsandbytes, trl, qwen-vl-utils |
| `vidlada` | `~/venvs/vidlada` | 3.10 | upstream pins: torch 2.5.1, transformers 4.43.4, deepspeed 0.14.4, peft 0.9.0, bitsandbytes 0.45.3, `llava` (editable, `~/code/VidLaDA/train`), `lmms_eval` (editable) |

Type `qwen3vl` or `vidlada` to activate, `deactivate` to leave.
Rebuild / repair: `bash ~/code/build-envs.sh ~/venvs ~/code` (idempotent).
Install extra packages with `uv pip install <pkg>` inside an activated venv.

## Models (already in `~/data/hf-cache`)
- `Qwen/Qwen3-VL-8B-Instruct` — standard `transformers` (`Qwen3VLForConditionalGeneration`).
- `ziHoHe/VidLaDA-8B` — must be loaded through the repo code, **not** plain `AutoModel`
  (the HF repo has no `modeling_llada.py`):
  `from llava.model.builder import load_pretrained_model`
  `load_pretrained_model("ziHoHe/VidLaDA-8B", None, "llava_vidlada", torch_dtype="float16", attn_implementation="sdpa", device_map="cuda:0", multimodal=True)`
  (model_name must contain `vidlada`). Conversation template: `llava_llada`.
- `google/siglip2-so400m-patch14-384` — VidLaDA's vision tower.
- `GSAI-ML/LLaDA-V` — tokenizer/config files only (no weights): the repo's `llava_llada`
  conversation template loads its chat template from there.
- 4-bit VidLaDA: upstream `load_4bit=True` is broken (passes `load_in_4bit` and `quantization_config` together);
  pass `quantization_config=BitsAndBytesConfig(...)` instead — see `~/code/examples/vidlada_infer.py`.

## Example commands
```bash
bash ~/code/examples/make_test_video.sh            # -> ~/data/test_video.mp4 (16 frames)
qwen3vl; python ~/code/examples/qwen3vl_infer_4bit.py   # Qwen3-VL 4-bit generation
qwen3vl; python ~/code/examples/qwen3vl_lora_4bit.py    # QLoRA, 3 steps, visual encoder frozen
vidlada; python ~/code/examples/vidlada_infer.py        # VidLaDA fp16 (add --4bit for NF4)
```
Gotcha: in your own scripts **import torch before decord** (in the vidlada env, `import decord` first and then
`deepspeed` segfaults). In qwen3vl, qwen-vl-utils must use the decord backend (`FORCE_QWENVL_VIDEO_READER=decord`,
already set in ~/.bashrc) because the installed torchvision no longer has `io.read_video`.

Each script prints peak VRAM. Use them as starting points for your own scripts.
On a 24 GB GPU: use 4-bit (QLoRA) + gradient checkpointing for 8B fine-tuning, keep frames/resolution modest.

## GPU etiquette (shared GPU)
1. **Check before you start**: `nvidia-smi` (or `gpu`). If someone else's job is running, wait or ask.
2. **One job at a time**, one GPU process per user.
3. Run long jobs in `tmux` (`tmux new -s train`, detach `Ctrl-b d`, reattach `tmux a -t train`) so they survive disconnects.
4. Keep a single job to **~24 h max**; checkpoint regularly so it can be stopped and resumed.
5. Kill your stale processes (`nvidia-smi` -> `kill <pid>`); do not leave notebooks holding VRAM.
6. `nvtop` gives a live per-process view.
R
chown "$U:$U" "$UH/README.md"
res PASS "README.md written"

# ------------------------------------------------------------------ 6. light smoke tests as the student
# Light only (admin decision): imports + CUDA bf16 matmul + bnb nf4 kernel + cache readable offline.
# NO 8B model loads here; the student runs ~/code/examples/*.py later (see README).
hdr "6. light smoke tests as $U"
SMOKE_OUT=$(sudo -u "$U" -H bash -s <<'T'
export LC_ALL=C
unset HUGGINGFACE_HUB_CACHE HF_TOKEN
export HF_HOME=$HOME/data/hf-cache HF_HUB_CACHE=$HOME/data/hf-cache/hub HF_HUB_OFFLINE=1
export XDG_CACHE_HOME=$HOME/data/.cache TRITON_CACHE_DIR=$HOME/data/.cache/triton
for e in qwen3vl vidlada; do
  ~/venvs/$e/bin/python - >/tmp/smoke-$e-$$.log 2>&1 <<'PY'
import torch, transformers, peft, bitsandbytes as bnb
assert torch.cuda.is_available()
x = torch.randn(1024, 1024, device="cuda", dtype=torch.bfloat16)
assert torch.isfinite((x @ x).float()).all()
lin = bnb.nn.Linear4bit(256, 256, compute_dtype=torch.bfloat16, quant_type="nf4").cuda()
lin(torch.randn(4, 256, device="cuda", dtype=torch.bfloat16))
print("torch", torch.__version__, "transformers", transformers.__version__, "peft", peft.__version__, "bnb", bnb.__version__)
PY
  if [ $? = 0 ]; then echo "RESULT PASS $e: imports + CUDA bf16 matmul + bnb nf4 ($(tail -1 /tmp/smoke-$e-$$.log))"
  else echo "RESULT FAIL $e: imports/CUDA"; tail -5 /tmp/smoke-$e-$$.log | sed 's/^/    /'; fi
  rm -f /tmp/smoke-$e-$$.log
done
~/venvs/vidlada/bin/python -c "import torch, deepspeed, decord, llava.model.builder, lmms_eval" >/dev/null 2>&1 \
  && echo "RESULT PASS vidlada: llava/lmms_eval/deepspeed/decord import" || echo "RESULT FAIL vidlada: llava/lmms_eval/deepspeed/decord import"
~/venvs/qwen3vl/bin/python -c "import torch, qwen_vl_utils, decord; from transformers import AutoProcessor, Qwen3VLForConditionalGeneration; AutoProcessor.from_pretrained('Qwen/Qwen3-VL-8B-Instruct')" >/dev/null 2>&1 \
  && echo "RESULT PASS qwen3vl: processor loads offline from ~/data/hf-cache" || echo "RESULT FAIL qwen3vl: processor offline load"
bash ~/code/examples/make_test_video.sh ~/data/test_video.mp4 >/dev/null 2>&1 && echo "RESULT PASS test video (~/data/test_video.mp4)" || echo "RESULT FAIL test video"
T
)
echo "$SMOKE_OUT"
while IFS= read -r l; do
  case "$l" in "RESULT "*) set -- $l; st=$2; shift 2; res "$st" "smoke: $*";; esac
done <<< "$SMOKE_OUT"

# ------------------------------------------------------------------ 7. cleanup
hdr "7. cleanup"
if [ $FAILED = 0 ]; then
  rm -rf "$STAGE" && res PASS "staging dir removed ($STAGE)"
else
  echo "Not removing staging dir because something failed. After fixing, remove with:"
  echo "  sudo rm -rf $STAGE"
fi

# ------------------------------------------------------------------ summary
hdr "SUMMARY"
for r in "${RESULTS[@]}"; do echo "  $r"; done
if [ $FAILED = 0 ]; then echo "OVERALL: PASS"; exit 0; else echo "OVERALL: FAIL"; exit 1; fi
