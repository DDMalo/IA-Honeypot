# Evaluation

Reference: `adjudicated`, 140 of 140 items, taxonomy v1.
Sample: seed 1, drawn 2026-11-03T18:38:23.285230+00:00, 60 uniform + 20 per class.
The labelled items stand for 155,001 of 156,739 sessions (98.9%); the largest single item is 103,209 (67% of them), so accuracy by session mostly says whether that one item is right.

Agreement between labellers:
- claude vs david: 105/140 intents agree (75%), Cohen's kappa 0.70

## Summary

| Classifier | Items | Failures | Accuracy | Macro-F1 | Accuracy, uniform | Macro-F1, uniform | Accuracy by session |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| majority class | 140 | — | 0.21 | 0.04 | 0.40 | 0.07 | 0.74 |
| rules | 140 | 0 | 0.74 | 0.69 | 0.80 | 0.72 | 0.90 |
| gemini:gemini-3.5-flash-lite | 140 | 0 | 0.85 | 0.78 | 0.80 | 0.64 | 0.89 |
| ollama:qwen2.5:1.5b | 140 | 0 | 0.17 | 0.11 | 0.17 | 0.07 | 0.05 |

Paired comparison (exact McNemar test on the items both answered):

| First | Second | Only first right | Only second right | p |
| --- | --- | ---: | ---: | ---: |
| rules | gemini:gemini-3.5-flash-lite | 12 | 28 | 0.0166 |
| rules | ollama:qwen2.5:1.5b | 79 | 0 | 0.0000 |
| gemini:gemini-3.5-flash-lite | ollama:qwen2.5:1.5b | 98 | 3 | 0.0000 |

## rules

| Part | Items | Accuracy | Macro-F1 | Baseline accuracy | Baseline macro-F1 |
| --- | ---: | ---: | ---: | ---: | ---: |
| all | 140 | 0.74 | 0.69 | 0.21 | 0.04 |
| uniform | 60 | 0.80 | 0.72 | 0.40 | 0.07 |
| stratified | 80 | 0.69 | 0.50 | 0.25 | 0.05 |

Accuracy by session (weighted): 0.90.

| Intent | Precision | Recall | F1 | Support | Recall, uniform | Support, uniform |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| credential_access | 0.67 | 0.50 | 0.57 | 4 | 1.00 | 1 |
| fingerprinting | 0.75 | 0.65 | 0.70 | 23 | 0.71 | 14 |
| other | 0.05 | 0.25 | 0.08 | 4 | 0.00 | 2 |
| persistence | 1.00 | 1.00 | 1.00 | 20 | 1.00 | 1 |
| protocol_probe | 1.00 | 0.91 | 0.95 | 22 | 0.50 | 2 |
| resource_profiling | 0.75 | 1.00 | 0.86 | 12 | 1.00 | 2 |
| shell_probing | 0.62 | 0.50 | 0.55 | 26 | 0.93 | 14 |
| staging | 1.00 | 0.69 | 0.82 | 29 | 0.83 | 24 |

Confusion matrix (rows: reference, columns: prediction):

| | protocol probe | credential access | fingerprinting | shell probing | resource profiling | staging | persistence | other |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| protocol_probe | 20 | 0 | 2 | 0 | 0 | 0 | 0 | 0 |
| credential_access | 0 | 2 | 0 | 0 | 0 | 0 | 0 | 2 |
| fingerprinting | 0 | 0 | 15 | 3 | 0 | 0 | 0 | 5 |
| shell_probing | 0 | 0 | 1 | 13 | 0 | 0 | 0 | 12 |
| resource_profiling | 0 | 0 | 0 | 0 | 12 | 0 | 0 | 0 |
| staging | 0 | 0 | 1 | 4 | 4 | 20 | 0 | 0 |
| persistence | 0 | 0 | 0 | 0 | 0 | 0 | 20 | 0 |
| other | 0 | 1 | 1 | 1 | 0 | 0 | 0 | 1 |

Latency per item: median 0.00 s, p90 0.00 s, total 0.2 s. No model was called, so there is no token cost.

## gemini:gemini-3.5-flash-lite

| Part | Items | Accuracy | Macro-F1 | Baseline accuracy | Baseline macro-F1 |
| --- | ---: | ---: | ---: | ---: | ---: |
| all | 140 | 0.85 | 0.78 | 0.21 | 0.04 |
| uniform | 60 | 0.80 | 0.64 | 0.40 | 0.07 |
| stratified | 80 | 0.89 | 0.83 | 0.25 | 0.05 |

Accuracy by session (weighted): 0.89.

| Intent | Precision | Recall | F1 | Support | Recall, uniform | Support, uniform |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| credential_access | 0.50 | 1.00 | 0.67 | 4 | 1.00 | 1 |
| fingerprinting | 0.75 | 0.52 | 0.62 | 23 | 0.50 | 14 |
| other | 1.00 | 0.25 | 0.40 | 4 | 0.00 | 2 |
| persistence | 1.00 | 0.95 | 0.97 | 20 | 1.00 | 1 |
| protocol_probe | 0.96 | 1.00 | 0.98 | 22 | 1.00 | 2 |
| resource_profiling | 0.90 | 0.75 | 0.82 | 12 | 0.50 | 2 |
| shell_probing | 0.74 | 0.88 | 0.81 | 26 | 0.86 | 14 |
| staging | 0.91 | 1.00 | 0.95 | 29 | 1.00 | 24 |

Confusion matrix (rows: reference, columns: prediction):

| | protocol probe | credential access | fingerprinting | shell probing | resource profiling | staging | persistence | other |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| protocol_probe | 22 | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| credential_access | 0 | 4 | 0 | 0 | 0 | 0 | 0 | 0 |
| fingerprinting | 0 | 2 | 12 | 8 | 0 | 1 | 0 | 0 |
| shell_probing | 0 | 1 | 1 | 23 | 1 | 0 | 0 | 0 |
| resource_profiling | 0 | 0 | 3 | 0 | 9 | 0 | 0 | 0 |
| staging | 0 | 0 | 0 | 0 | 0 | 29 | 0 | 0 |
| persistence | 0 | 0 | 0 | 0 | 0 | 1 | 19 | 0 |
| other | 1 | 1 | 0 | 0 | 0 | 1 | 0 | 1 |

Latency per item: median 3.98 s, p90 4.45 s, total 616.5 s. Estimated input: 926 tokens per item (characters / 4).

## ollama:qwen2.5:1.5b

| Part | Items | Accuracy | Macro-F1 | Baseline accuracy | Baseline macro-F1 |
| --- | ---: | ---: | ---: | ---: | ---: |
| all | 140 | 0.17 | 0.11 | 0.21 | 0.04 |
| uniform | 60 | 0.17 | 0.07 | 0.40 | 0.07 |
| stratified | 80 | 0.17 | 0.08 | 0.25 | 0.05 |

Accuracy by session (weighted): 0.05.

| Intent | Precision | Recall | F1 | Support | Recall, uniform | Support, uniform |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| credential_access | 0.00 | 0.00 | 0.00 | 4 | 0.00 | 1 |
| fingerprinting | never predicted | 0.00 | 0.00 | 23 | 0.00 | 14 |
| other | 0.00 | 0.00 | 0.00 | 4 | 0.00 | 2 |
| persistence | never predicted | 0.00 | 0.00 | 20 | 0.00 | 1 |
| protocol_probe | 0.57 | 0.18 | 0.28 | 22 | 0.00 | 2 |
| resource_profiling | 0.14 | 1.00 | 0.24 | 12 | 1.00 | 2 |
| shell_probing | 0.35 | 0.31 | 0.33 | 26 | 0.57 | 14 |
| staging | never predicted | 0.00 | 0.00 | 29 | 0.00 | 24 |

Confusion matrix (rows: reference, columns: prediction):

| | protocol probe | credential access | fingerprinting | shell probing | resource profiling | staging | persistence | other |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| protocol_probe | 4 | 0 | 0 | 0 | 3 | 0 | 0 | 15 |
| credential_access | 0 | 0 | 0 | 0 | 4 | 0 | 0 | 0 |
| fingerprinting | 1 | 1 | 0 | 1 | 18 | 0 | 0 | 2 |
| shell_probing | 2 | 0 | 0 | 8 | 15 | 0 | 0 | 1 |
| resource_profiling | 0 | 0 | 0 | 0 | 12 | 0 | 0 | 0 |
| staging | 0 | 4 | 0 | 13 | 12 | 0 | 0 | 0 |
| persistence | 0 | 0 | 0 | 1 | 19 | 0 | 0 | 0 |
| other | 0 | 0 | 0 | 0 | 4 | 0 | 0 | 0 |

Latency per item: median 11.48 s, p90 32.48 s, total 2926.3 s. Estimated input: 926 tokens per item (characters / 4).
