"""
Standalone sanity check - confirms your OPENAI_API_KEY works and the
Agents SDK can make a real API call, with zero dependency on Flask,
your database, or any of the actual assignment logic.

Run this FIRST, before testing the real feature, so that if something
fails, you know immediately whether it's a key/billing problem or
something in your app-specific code.

Usage:
    python test_agent_key.py
"""

import os
from dotenv import load_dotenv

load_dotenv()

print("Checking for OPENAI_API_KEY...")
key = os.getenv("OPENAI_API_KEY")
if not key:
    print("MISSING - OPENAI_API_KEY not found. Check your .env file.")
    exit(1)
print(f"Found key starting with: {key[:12]}...")

from agents import Agent, Runner

test_agent = Agent(
    name="TestAgent",
    instructions="You are a test agent. Just respond with a short friendly confirmation message.",
)

print("Calling the OpenAI API...")
result = Runner.run_sync(test_agent, "Say hello and confirm you're working.")

print("\n--- SUCCESS ---")
print(result.final_output)
