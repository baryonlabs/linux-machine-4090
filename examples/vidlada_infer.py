"""VidLaDA-8B through the repo's own code path (llava package), one generation on a video.
Usage (venv vidlada):  python vidlada_infer.py [video.mp4] [--4bit]
Default precision is fp16, the same as the upstream lmms-eval wrapper.
"""
import os, sys, time, copy, torch, numpy as np
from decord import VideoReader, cpu
from llava.model.builder import load_pretrained_model
from llava.mm_utils import tokenizer_image_token
from llava.constants import IMAGE_TOKEN_INDEX, DEFAULT_IMAGE_TOKEN
from llava.conversation import conv_templates
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from gpu_check import gpu_free_or_exit, report

MODEL = os.environ.get("VIDLADA_MODEL", "ziHoHe/VidLaDA-8B")
args = [a for a in sys.argv[1:] if not a.startswith("--")]
video = args[0] if args else os.path.expanduser("~/data/test_video.mp4")
four_bit = "--4bit" in sys.argv
gpu_free_or_exit(10 if four_bit else 20)

# NOTE: upstream builder.py's load_4bit=True passes both load_in_4bit and quantization_config,
# which transformers 4.43 rejects -> pass our own quantization_config instead.
extra = {}
if four_bit:
    from transformers import BitsAndBytesConfig
    extra["quantization_config"] = BitsAndBytesConfig(
        load_in_4bit=True, bnb_4bit_quant_type="nf4", bnb_4bit_use_double_quant=True,
        bnb_4bit_compute_dtype=torch.float16, llm_int8_skip_modules=["mm_projector", "vision_tower", "lm_head"])
t0 = time.time()
tok, model, proc, _ = load_pretrained_model(
    MODEL, None, "llava_vidlada", torch_dtype="float16", **extra,
    attn_implementation="sdpa", device_map="cuda:0", multimodal=True,
    overwrite_config={"mm_spatial_pool_stride": 2, "mm_spatial_pool_mode": "bilinear", "mm_newline_position": "grid"})
model.eval()
print(f"loaded ({'4bit' if four_bit else 'fp16'}) in {time.time()-t0:.0f}s"); report("after load")

vr = VideoReader(video, ctx=cpu(0))
idx = np.linspace(0, len(vr) - 1, min(16, len(vr)), dtype=int).tolist()
frames = vr.get_batch(idx).asnumpy()
pix = proc.preprocess(frames, return_tensors="pt")["pixel_values"].to("cuda", torch.float16)

conv = copy.deepcopy(conv_templates["llava_llada"])
conv.append_message(conv.roles[0], DEFAULT_IMAGE_TOKEN + "\nDescribe this video in one sentence.")
conv.append_message(conv.roles[1], None)
ids = tokenizer_image_token(conv.get_prompt(), tok, IMAGE_TOKEN_INDEX, return_tensors="pt").unsqueeze(0).cuda()
pad = tok.pad_token_id if tok.pad_token_id is not None else tok.eos_token_id
t0 = time.time()
with torch.inference_mode():
    out = model.generate(ids, attention_mask=ids.ne(pad), pad_token_id=pad, images=[pix], modalities=["video"],
                         use_cache=False, steps=32, gen_length=32, block_length=32, temperature=0.0,
                         cfg=0, remasking="low_confidence", tokenizer=tok, stopping_criteria=[conv.sep])
print(f"generation {time.time()-t0:.1f}s ->", repr(tok.batch_decode(out, skip_special_tokens=True)[0].strip()))
report("after generate")
print("VIDLADA_INFER_OK")
