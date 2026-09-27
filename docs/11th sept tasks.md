1. pytest unit tests / FastAPI smoke test
Problem before: no automated way to know if a code change silently breaks the running system. The only way to find out inference_server.py still works was to manually start it and poke it by hand.
What it solves: a script now asserts, in ~10 seconds, "the server starts, /predict returns a sane response for valid input, rejects malformed input correctly." That assertion runs the same way every time, by anyone, without a human remembering all the manual steps.
MLOps significance: this is the base layer of trust an ML system needs before anything downstream can be automated. Later in goals.md, code gets auto-deployed to a live server and models get auto-retrained/auto-promoted with no human in the loop — none of that is safe to automate unless you already trust that a change didn't break basic correctness. Tests are what let you trust code you haven't personally re-read.

2. ruff (linter)
Problem before: nothing checked the code for actual defects that don't crash anything but are still wrong — an unused import, a variable named l that's visually indistinguishable from 1. These aren't caught by tests (the code still runs), only by reading every line carefully.
What it solves: it read every file and genuinely found two real, live issues — a dead ICMP import in stream_processor.py and three l/1-confusable variable names in inference_server.py — that I then fixed.
MLOps significance: this is a cheap, automatic second pair of eyes. In a pipeline with unattended retraining jobs, small defects like this are exactly the kind of thing that quietly rot until someone's debugging a 2am pipeline failure.

3. black (formatter)
Problem before: code style (spacing, line wrapping, quote style) was whatever each edit happened to produce — no enforced consistency.
What it solves: rewrote the files into one canonical style automatically, so every file looks like it was written by the same hand.
MLOps significance: smaller than it sounds for a solo project, but it matters once retraining/CI scripts start generating diffs (e.g. an automated job that updates a version string) — consistent formatting means git diff only shows the actual change, not incidental reformatting noise on top of it.

4. pre-commit (config written, not yet installed)
Problem it's meant to solve: ruff and black only help if someone actually runs them before committing — and that's a step that's easy to forget under time pressure. pre-commit moves that check from "a thing you have to remember" to "a thing that happens automatically the moment you type git commit," and blocks the commit if it fails.
MLOps significance: this is the earliest possible point in the pipeline to catch a problem — before the commit even exists, versus discovering it minutes later when CI fails on GitHub. It's not a replacement for CI (CI is still the real enforcement backstop, since pre-commit is opt-in per machine), it's a fast local first line of defense.

Together, these four are what claude/goals.md calls the "DevOps floor" — the Week 1 checkpoint is literally "every push runs lint + tests automatically." Nothing later in the plan (Docker image builds, cloud auto-deploy, MLflow model registry, guarded auto-promotion of retrained models) is trustworthy to run unattended until this floor exists, because all of those later steps assume "if it's in main, it's known-good" — and that assumption is only true because of the tests/lint/pre-commit/CI chain.

