## Problem Statement & Instructions
Ghost Data Still Exists
Northstar Shop (an imaginary company) lost $2.4 million after one supposedly deleted customer came back as a ghost in its systems. Every internal dashboard showed the deletion request as “Complete.” Weeks later, the same customer tried to create a new account. The platform refused: “This email is already registered.”

What looked like a simple signup bug exposed a much larger failure. The investigation uncovered personal data across secondary databases, support attachments, search indexes, analytics exports, logs, archives, and backups. A synchronization job had even recreated information that the primary account service had successfully deleted.

They now needs an AI-powered deletion audit agent that can prove whether a user's personal data is truly gone before another failure causes financial and reputational damage.

The agent must investigate the supplied records, determine the user's current and historical identifiers, reconstruct what happened across systems, and decide whether the deletion is actually complete.

When data remains, the agent must produce the ordered remediation steps required to remove, redact, or anonymize it. When deletion has already been completed, the agent must produce the checks that prove it. The agent must also preserve records that the supplied policy requires the organization to retain.

What You Need to Build
For each request, build a system that determines:

whether the deletion is COMPLETE, INCOMPLETE, or NOT_APPLICABLE because the person did not request deletion;
which records or identifiers still expose the user;
which active processes can recreate deleted data;
the ordered remediation steps required to complete the request.
A deletion is complete only when:

every relevant copy has received the treatment required by deletion_rules.csv;
no active sync, import, or restore path can recreate the data;
retained records contain only the identifiers permitted by the rules; and
records that must be retained remain available.
Read the detailed problem statement here - E:\hackerrank-orchestrate-october26\problem_statement.md

## Deletion Requests
A set of deletion requests is provided. Some include expected output for validation; others do not. Run all requests with your agent and submit the results as a CSV.
E:\hackerrank-orchestrate-october26\dataset\deletion_requests.csv

## Requirements:
Must read the provided CSV files and local media files.
Must produce output.csv with the exact schema in problem_statement.md.
Must include an evaluation workflow
Must avoid hardcoded test labels or file-specific answers.
Beyond that you are free to bring your own approach and innovation: VLMs, LLMs, structured prompting, evaluation pipelines, model comparison, or anything else.

## Submissions
Clone the repo from Github to get started
You will upload three files on HackerRank Platform:

Code zip: zip your code/ directory and upload it. Exclude virtualenvs, node_modules, build artifacts, the data/ corpus, and the dataset/ folder.
Predictions CSV: your agent's output for dataset/deletion_requests.csv (i.e. the populated output.csv).
Chat transcript: the log.txt from the path in https://github.com/interviewstreet/hackerrank-orchestrate-october26#chat-transcript-logging