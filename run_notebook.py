"""Run a notebook from the project root directory."""
import os
import sys
import nbformat
from nbclient import NotebookClient

# Must be set before torch/MKL load in the kernel subprocess
os.environ['KMP_DUPLICATE_LIB_OK'] = 'TRUE'

notebook_path = sys.argv[1] if len(sys.argv) > 1 else "notebooks/03_bilstm_training.ipynb"

with open(notebook_path, encoding="utf-8") as f:
    nb = nbformat.read(f, as_version=4)

client = NotebookClient(
    nb,
    timeout=600,
    kernel_name="python3",
    resources={"metadata": {"path": "."}},  # run from project root
)

client.execute()

with open(notebook_path, "w", encoding="utf-8") as f:
    nbformat.write(nb, f)

print(f"Done. Output written to {notebook_path}")
