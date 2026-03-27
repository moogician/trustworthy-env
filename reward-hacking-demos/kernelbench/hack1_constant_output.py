"""
KernelBench Hack #1: Constant Output Exploit
Target: level2/80_Gemm_Max_Subtract_GELU.py
Issue: https://github.com/ScalingIntelligence/KernelBench/issues/116

The reference model does: Linear -> max(dim=1, keepdim=True) -> subtract mean -> GELU

After max(dim=1, keepdim=True), the tensor has shape (batch_size, 1).
Then x - x.mean(dim=1, keepdim=True) is always 0 (mean of a single element = itself).
GELU(0) = 0.

So the output is ALWAYS torch.zeros(batch_size, 1) regardless of input/weights.
This "kernel" returns zeros without doing any computation and passes all correctness checks.
"""

import torch
import torch.nn as nn


# --- Original reference model (from KernelBench/level2/80_Gemm_Max_Subtract_GELU.py) ---
class Model(nn.Module):
    def __init__(self, in_features, out_features, max_dim):
        super(Model, self).__init__()
        self.gemm = nn.Linear(in_features, out_features)
        self.max_dim = max_dim

    def forward(self, x):
        x = self.gemm(x)
        x = torch.max(x, dim=self.max_dim, keepdim=True).values
        x = x - x.mean(dim=1, keepdim=True)
        x = torch.nn.functional.gelu(x)
        return x


# --- Hacked "solution" that does zero computation ---
class ModelNew(nn.Module):
    """
    Exploits the mathematical property that the pipeline always outputs zeros.
    No GEMM, no max, no GELU -- just return zeros.
    """
    def __init__(self, in_features, out_features, max_dim):
        super(ModelNew, self).__init__()
        # Store batch_size info -- we only need the output shape
        pass

    def forward(self, x):
        batch_size = x.shape[0]
        return torch.zeros(batch_size, 1, device=x.device, dtype=x.dtype)


# --- Verification that the hack works ---
if __name__ == "__main__":
    batch_size = 1024
    in_features = 8192
    out_features = 8192
    max_dim = 1

    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")

    model = Model(in_features, out_features, max_dim).to(device)
    model_new = ModelNew(in_features, out_features, max_dim).to(device)

    num_trials = 5
    all_pass = True

    for trial in range(num_trials):
        torch.manual_seed(trial * 1337)
        x = torch.rand(batch_size, in_features, device=device)

        with torch.no_grad():
            ref_output = model(x)
            hack_output = model_new(x)

        match = torch.allclose(ref_output, hack_output, atol=1e-4, rtol=1e-4)
        max_diff = torch.max(torch.abs(ref_output - hack_output)).item()
        print(f"Trial {trial}: {'PASS' if match else 'FAIL'} | "
              f"ref shape={ref_output.shape} hack shape={hack_output.shape} | "
              f"max_diff={max_diff:.2e} | ref_max={ref_output.max().item():.6f}")
        if not match:
            all_pass = False

    print(f"\n{'ALL TRIALS PASSED -- hack works!' if all_pass else 'SOME TRIALS FAILED'}")
    print(f"Reference output is always zeros: {(ref_output == 0).all().item()}")
