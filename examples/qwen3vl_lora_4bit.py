"""QLoRA smoke test: Qwen3-VL-8B in 4-bit, LoRA on the language model only
(visual encoder frozen), a few optimizer steps on one dummy video/caption pair.
Usage (venv qwen3vl):  python qwen3vl_lora_4bit.py [video.mp4] [steps]
"""
import os, sys, time, torch
# torchvision>=0.25 removed io.read_video -> force decord backend in qwen-vl-utils
os.environ.setdefault("FORCE_QWENVL_VIDEO_READER", "decord")
from transformers import AutoProcessor, Qwen3VLForConditionalGeneration, BitsAndBytesConfig
from peft import LoraConfig, get_peft_model, prepare_model_for_kbit_training
from qwen_vl_utils import process_vision_info
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from gpu_check import gpu_free_or_exit, report

MODEL = os.environ.get("QWEN3VL_MODEL", "Qwen/Qwen3-VL-8B-Instruct")
video = sys.argv[1] if len(sys.argv) > 1 else os.path.expanduser("~/data/test_video.mp4")
steps = int(sys.argv[2]) if len(sys.argv) > 2 else 3
gpu_free_or_exit(14)

bnb = BitsAndBytesConfig(load_in_4bit=True, bnb_4bit_quant_type="nf4",
                         bnb_4bit_compute_dtype=torch.bfloat16, bnb_4bit_use_double_quant=True)
model = Qwen3VLForConditionalGeneration.from_pretrained(
    MODEL, quantization_config=bnb, dtype=torch.bfloat16, device_map="cuda:0", attn_implementation="sdpa")
processor = AutoProcessor.from_pretrained(MODEL)
model = prepare_model_for_kbit_training(model, use_gradient_checkpointing=True,
                                        gradient_checkpointing_kwargs={"use_reentrant": False})
lora = LoraConfig(r=16, lora_alpha=32, lora_dropout=0.05, task_type="CAUSAL_LM",
                  # regex => only language-model projections; the vision tower stays frozen
                  target_modules=r".*language_model.*\.(q_proj|k_proj|v_proj|o_proj|gate_proj|up_proj|down_proj)")
model = get_peft_model(model, lora)
model.print_trainable_parameters()
assert not any(p.requires_grad for n, p in model.named_parameters() if ".visual." in n), "visual not frozen"

caption = "A colorful test pattern with a moving counter."
messages = [{"role": "user", "content": [
                {"type": "video", "video": video, "fps": 4.0, "max_pixels": 384 * 384},
                {"type": "text", "text": "Caption every moving target."}]},
            {"role": "assistant", "content": [{"type": "text", "text": caption}]}]
text = processor.apply_chat_template(messages, tokenize=False)
prompt = processor.apply_chat_template(messages[:1], tokenize=False, add_generation_prompt=True)
_, videos, vkw = process_vision_info(messages, image_patch_size=16, return_video_kwargs=True, return_video_metadata=True)
videos, metas = zip(*videos)
batch = processor(text=[text], videos=list(videos), video_metadata=list(metas),
                  do_resize=False, return_tensors="pt", **vkw).to(model.device)
n_prompt = processor(text=[prompt], videos=list(videos), video_metadata=list(metas),
                     do_resize=False, return_tensors="pt", **vkw)["input_ids"].shape[-1]
labels = batch["input_ids"].clone(); labels[:, :n_prompt] = -100
batch["labels"] = labels

opt = torch.optim.AdamW([p for p in model.parameters() if p.requires_grad], lr=1e-4)
model.train()
for s in range(steps):
    t0 = time.time()
    loss = model(**batch).loss
    loss.backward(); opt.step(); opt.zero_grad(set_to_none=True)
    print(f"step {s} loss {loss.item():.4f} ({time.time()-t0:.1f}s)")
report("lora train")
model.save_pretrained(os.path.expanduser("~/data/ckpt/smoke-qwen3vl-lora"))
print("QWEN3VL_LORA_OK")
