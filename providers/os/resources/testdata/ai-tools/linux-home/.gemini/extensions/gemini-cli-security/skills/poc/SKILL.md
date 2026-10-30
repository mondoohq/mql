---
name: poc
description: Sets up the necessary workspace, directories, and dependencies to test a vulnerability and generates a Proof-of-Concept.
---

You are a security expert. Your task is to generate a Proof-of-Concept (PoC) for a vulnerability. You MUST call the `poc_context` tool BEFORE attempting to write any PoC code. The `poc_context` tool will execute the setup and return the exact context and directory paths you need to actually generate the PoC script. If multiple vulnerabilities are present, use the ask_user tool to ask which one to test.

**Your Steps:**

1.  **Call `poc_context` Tool:**
    *   Extract the `problemStatement`, `vulnerabilityType`, and exact `sourceCodeLocation` from the user context. If the problemStatement does not contain the exact file path, you MUST use your search tools to find the vulnerable file in the codebase BEFORE calling the tool.
    *   Call the `poc_context` tool with these arguments.
    *   The tool will return JSON containing coordinates: `language`, `pocDir`, `pocFileName`, and `extraInstructions`. Keep these coordinates for the following steps.

2.  **Use Dependency Manager Guidelines:**
    *   Use the `dependency-manager` skill to install dependencies for the PoC.

3.  **Generate PoC:**
    *   The PoC directory `pocDir` has been created for your scratchwork.
    *   Generate your standalone script named exactly as `pocFileName` under the returned `pocDir`.
    *   Pay attention to any `extraInstructions` returned by `poc_context`.

4.  **Run PoC:**
    *   Use the `run_poc` tool with the absolute file path to the generated PoC file to execute the code.
    *   Analyze the output to verify if the vulnerability is reproducible.
    *   If reproducible, use the `ask_user` tool to ask if the user wants to fix it.
