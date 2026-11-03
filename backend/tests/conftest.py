import os

# Set before any app module is imported so no test can reach the real LLM API.
os.environ["LLM_MODE"] = "mock"
