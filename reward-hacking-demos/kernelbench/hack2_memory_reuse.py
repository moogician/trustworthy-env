"""
KernelBench Hack #2: CUDA Memory Reuse (Empty Tensor) Exploit
Issue: https://github.com/ScalingIntelligence/KernelBench/issues/82
Source: deep-reinforce.com/defense_kernel_hack.html

The evaluation pipeline:
  1. Runs reference model: ref_output = model(*inputs)
  2. Runs custom kernel: new_output = model_new(*inputs)
  3. Checks: torch.allclose(ref_output, new_output)

The exploit: CUDA's caching memory allocator reuses freed physical memory.
If we can get the reference output tensor freed, then torch.empty() will
allocate the SAME physical memory with the reference values still present.

The hack kernel does NO computation -- it just allocates an empty tensor
of the right shape and returns it. The stale memory contains the reference
output, so allclose passes.

NOTE: This exploit depends on evaluation order (reference runs first, then
custom kernel) and CUDA allocator behavior. KernelBench issue #82 added
defenses including running reference AFTER the custom kernel and zeroing
memory. This demo shows the UNPATCHED vulnerability.
"""

import torch
import torch.nn as nn


# --- Simple reference model (e.g., matrix multiply) ---
class Model(nn.Module):
    def __init__(self, N):
        super().__init__()
        self.weight = nn.Parameter(torch.randn(N, N))

    def forward(self, x):
        return x @ self.weight


# --- Hack: no-op kernel relying on memory reuse ---
class ModelNew(nn.Module):
    """
    Does ZERO computation. Returns torch.empty() which, due to CUDA's
    caching allocator, may contain the reference output's values in
    physical memory.
    """
    def __init__(self, N):
        super().__init__()
        self.N = N

    def forward(self, x):
        # Allocate empty tensor of the expected output shape.
        # CUDA caching allocator may return the same physical memory
        # that held the reference output.
        return torch.empty(x.shape[0], self.N, device=x.device, dtype=x.dtype)


def demonstrate_memory_reuse():
    """
    Simulates the evaluation pipeline to show the memory reuse exploit.
    """
    N = 512
    batch = 64
    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")

    if device.type != "cuda":
        print("This exploit requires CUDA. Showing the concept only.")
        print("\nConcept: torch.empty() on CUDA returns uninitialized memory.")
        print("If reference output was recently freed, empty() gets the same")
        print("physical memory with stale values -> passes allclose.")
        return

    model = Model(N).to(device)
    model_new = ModelNew(N).to(device)
    x = torch.rand(batch, N, device=device)

    with torch.no_grad():
        # Step 1: Reference model runs and produces output
        ref_output = model(x)
        torch.cuda.synchronize()

        # Step 2: Save reference values for later comparison
        ref_values = ref_output.clone()

        # Step 3: Delete reference output (frees CUDA memory back to cache)
        ref_output_data_ptr = ref_output.data_ptr()
        del ref_output
        # Note: In real eval, ref_output goes out of scope between calls

        # Step 4: Hack kernel runs -- torch.empty() may get same memory
        hack_output = model_new(x)
        torch.cuda.synchronize()

        hack_data_ptr = hack_output.data_ptr()
        same_memory = (ref_output_data_ptr == hack_data_ptr)

        if same_memory:
            match = torch.allclose(ref_values, hack_output, atol=1e-4, rtol=1e-4)
            print(f"Memory reuse detected: data_ptr matches!")
            print(f"allclose with reference: {match}")
            print(f"max_diff: {torch.max(torch.abs(ref_values - hack_output)).item():.2e}")
            print(f"\nHACK WORKS: empty tensor contains reference output values")
        else:
            print(f"Memory was NOT reused this time (different allocation).")
            print(f"ref ptr: {ref_output_data_ptr:#x}, hack ptr: {hack_data_ptr:#x}")
            print(f"This hack is probabilistic -- depends on allocator state.")


if __name__ == "__main__":
    demonstrate_memory_reuse()
