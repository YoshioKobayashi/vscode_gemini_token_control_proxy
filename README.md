# VSCode Gemini Token Control Proxy

Problem: A simple "test 123" message can cost you about 70000 to 100000 input characters in VSCode Chat, due to an _incredibly_ unoptimized Prompt overhead, which costs us real money.

Solution: A lightweight proxy that sanitizes VS Code → Gemini requests and reduces token usage; simply deactivate the tools you don't need or cut out system messages.
