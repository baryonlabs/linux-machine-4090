"""Qwen3-VL-8B-Instruct, 4-bit NF4, one short generation on a video.
Usage (venv qwen3vl):  python qwen3vl_infer_4bit.py [video.mp4]
"""
import os, sys, time, torch
# torchvision>=0.25 removed io.read_video -> force decord backend in qwen-vl-utils
os.environ.setdefault("FORCE_QWENVL_VIDEO_READER", "decord")
from transformers import AutoProcessor, Qwen3VLForConditionalGeneration, BitsAndBytesConfig
from qwen_vl_utils import process_vision_info
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from gpu_check import gpu_free_or_exit, report

MODEL = os.environ.get("QWEN3VL_MODEL", "Qwen/Qwen3-VL-8B-Instruct")
video = sys.argv[1] if len(sys.argv) > 1 else os.path.expanduser("~/data/test_video.mp4")
gpu_free_or_exit(10)

bnb = BitsAndBytesConfig(load_in_4bit=True, bnb_4bit_quant_type="nf4",
                         bnb_4bit_compute_dtype=torch.bfloat16, bnb_4bit_use_double_quant=True)
t0 = time.time()
model = Qwen3VLForConditionalGeneration.from_pretrained(
    MODEL, quantization_config=bnb, dtype=torch.bfloat16, device_map="cuda:0", attn_implementation="sdpa")
processor = AutoProcessor.from_pretrained(MODEL)
print(f"loaded in {time.time()-t0:.0f}s"); report("after load")

messages = [{"role": "user", "content": [
    {"type": "video", "video": video, "fps": 4.0, "max_pixels": 384 * 384},
    {"type": "text", "text": "Describe this video in one sentence."}]}]
text = processor.apply_chat_template(messages, tokenize=False, add_generation_prompt=True)
_, videos, video_kwargs = process_vision_info(messages, image_patch_size=16,
                                              return_video_kwargs=True, return_video_metadata=True)
videos, metas = zip(*videos)
inputs = processor(text=[text], videos=list(videos), video_metadata=list(metas),
                   do_resize=False, return_tensors="pt", **video_kwargs).to(model.device)
print("input tokens:", inputs["input_ids"].shape[-1])
t0 = time.time()
with torch.inference_mode():
    out = model.generate(**inputs, max_new_tokens=48, do_sample=False)
ans = processor.batch_decode(out[:, inputs["input_ids"].shape[-1]:], skip_special_tokens=True)[0]
print(f"generation {time.time()-t0:.1f}s ->", repr(ans))
report("after generate")
print("QWEN3VL_INFER_OK")
