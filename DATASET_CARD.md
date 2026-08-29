# Dataset Card: CTU-13 Host-Window Graph Representation

## Summary

This repository reconstructs a host-window graph derived from the thirteen official CTU-13 labeled bidirectional flow files. It supplies processing and validation code but does not redistribute CTU-13 or the generated artifact.

## Source and license

CTU-13 was created by the Stratosphere Laboratory at the Czech Technical University in Prague. The original dataset is available from https://www.stratosphereips.org/datasets-ctu13 under a Creative Commons Attribution license. The original terms remain applicable.

## Unit of analysis

Each node represents one IP address within one CTU-13 scenario and one global one-hour Unix-time window. Raw IP addresses are used for grouping but are not stored in the output feature matrix. Directed weighted edges represent aggregated source-to-destination communications within the same scenario and window.

## Labeling

A node is marked compromised when it is the source of at least one flow whose label contains `Botnet` or `Malicious`, case-insensitively. Destination nodes are not marked compromised solely because they receive a maliciously labeled flow.

## Composition

| Scenario | Nodes | Compromised |
|---:|---:|---:|
| 1 | 1,143,710 | 5 |
| 2 | 728,897 | 4 |
| 3 | 992,397 | 86 |
| 4 | 286,101 | 5 |
| 5 | 44,065 | 2 |
| 6 | 140,352 | 3 |
| 7 | 40,731 | 2 |
| 8 | 916,322 | 20 |
| 9 | 639,350 | 60 |
| 10 | 330,227 | 57 |
| 11 | 41,931 | 3 |
| 12 | 105,050 | 16 |
| 13 | 701,592 | 17 |
| **Total** | **6,110,725** | **280** |

The graph contains 6,737,390 directed edges and is extremely imbalanced.

## Features

The output matrix contains 67 float32 columns. Columns 0–60 are local traffic summaries covering activity, bytes, packets, duration, source bytes, port diversity, protocol, direction, selected service ports, connection states, and type-of-service fields. Columns 61–66 contain in-degree, out-degree, total degree, approximate betweenness, PageRank, and clustering. The article's principal experiments use only columns 0–60.

## Intended uses

- botnet detection research;
- scenario-level generalization experiments;
- comparison of tabular and graph-learning methods;
- reproducibility studies using CTU-13.

## Limitations

- CTU-13 was captured in 2011 and does not represent all contemporary traffic or malware families;
- a node is a device-window observation, not necessarily a unique physical machine;
- labeling depends on the original flow labels and the source-node rule;
- class prevalence is extremely low and varies substantially by scenario;
- graph topology depends on the one-hour aggregation interval;
- pickle serialization is Python-specific and must not be loaded from untrusted sources;
- the six original topological variables are precomputed on the full scenario graph representation and must be excluded when an experiment requires strictly local traffic features.

## Privacy

The generated feature matrix does not contain raw IP addresses, absolute timestamps, or original label strings. The scripts process IP addresses transiently to define nodes and edges.

## Validation

The repository records SHA-256 hashes for all thirteen inputs and validates output dimensions, dtypes, feature order, graph size, class counts, per-scenario distributions, and the serialized reference hash.
