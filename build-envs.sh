#!/usr/bin/env bash
# Build research envs for the video multi-target captioning project.
# Usage: bash build-envs.sh <ENV_DIR> <CODE_DIR>
#   student: bash build-envs.sh ~/venvs ~/code
# Idempotent: re-running only installs what is missing.
set -euo pipefail
export LC_ALL=C
ENV_DIR=${1:?env dir}; CODE_DIR=${2:?code dir}
mkdir -p "$ENV_DIR" "$CODE_DIR"
export UV_LINK_MODE=copy UV_HTTP_TIMEOUT=300
VIDLADA_COMMIT=${VIDLADA_COMMIT:-30bb1321c7bb02142e548831826818117cf95b2a}

ok(){ echo "[OK] $*"; }
hdr(){ echo; echo "=== $* ($(date '+%F %T'))"; }

# ---------------------------------------------------------------- qwen3vl (py3.12, current stack)
hdr qwen3vl
[ -x "$ENV_DIR/qwen3vl/bin/python" ] || uv venv --python 3.12 "$ENV_DIR/qwen3vl"
VIRTUAL_ENV="$ENV_DIR/qwen3vl" uv pip install \
  torch torchvision \
  "transformers>=4.57" accelerate peft bitsandbytes "qwen-vl-utils>=0.0.14" \
  datasets trl av decord opencv-python-headless einops timm \
  tensorboard wandb ipykernel huggingface_hub hf_xet nvidia-ml-py
ok qwen3vl

# ---------------------------------------------------------------- vidlada (py3.10, pinned by upstream)
hdr vidlada
if [ ! -d "$CODE_DIR/VidLaDA/.git" ]; then
  git clone https://github.com/ziHoHe/VidLaDA "$CODE_DIR/VidLaDA"
  git -C "$CODE_DIR/VidLaDA" checkout -q "$VIDLADA_COMMIT"
fi
[ -x "$ENV_DIR/vidlada/bin/python" ] || uv venv --python 3.10 "$ENV_DIR/vidlada"
export VIRTUAL_ENV="$ENV_DIR/vidlada"
uv pip install torch==2.5.1 torchvision==0.20.1 torchaudio==2.5.1 setuptools wheel ninja packaging
# same order as upstream init_env.sh: lmms-eval first, then train[train] so its pins
# (transformers 4.43.4, datasets 2.20.0, httpx 0.24.0, ...) win.
uv pip install -e "$CODE_DIR/VidLaDA/eval/lmms-eval" -e "$CODE_DIR/VidLaDA/eval/lmms-eval[metrics]"
# deepspeed 0.14.4 is an sdist whose setup.py imports torch -> no build isolation; no CUDA ops prebuilt
DS_BUILD_OPS=0 uv pip install --no-build-isolation-package deepspeed \
  torch==2.5.1 torchvision==0.20.1 -e "$CODE_DIR/VidLaDA/train[train]"
uv pip install torch==2.5.1 torchvision==0.20.1 "numpy<2" scikit-learn==1.7.2 pandas tensorboard ipykernel
unset VIRTUAL_ENV
ok vidlada

# ---------------------------------------------------------------- verify
for e in qwen3vl vidlada; do
  hdr "verify $e"
  "$ENV_DIR/$e/bin/python" - <<'PY'
import torch, transformers, peft, bitsandbytes as bnb
print("torch", torch.__version__, "cuda", torch.version.cuda, "available", torch.cuda.is_available())
print("transformers", transformers.__version__, "peft", peft.__version__, "bnb", bnb.__version__)
assert torch.cuda.is_available(), "CUDA not available"
x = torch.randn(2048, 2048, device="cuda", dtype=torch.bfloat16)
assert torch.isfinite((x @ x).float()).all(); print("bf16 matmul ok on", torch.cuda.get_device_name(0))
lin = bnb.nn.Linear4bit(256, 256, compute_dtype=torch.bfloat16, quant_type="nf4").cuda()
y = lin(torch.randn(4, 256, device="cuda", dtype=torch.bfloat16)); print("bnb nf4 kernel ok", tuple(y.shape))
PY
done
# NOTE: import torch BEFORE decord -- "import decord" first, then deepspeed => segfault (decord's bundled libs)
"$ENV_DIR/vidlada/bin/python" -c "import torch, numpy, deepspeed, decord, llava.model.builder, lmms_eval; print('vidlada stack ok: numpy', numpy.__version__, 'deepspeed', deepspeed.__version__)"
"$ENV_DIR/qwen3vl/bin/python" -c "import torch, qwen_vl_utils, av, decord; from transformers import Qwen3VLForConditionalGeneration; print('qwen3vl classes ok')"
echo BUILD_DONE
