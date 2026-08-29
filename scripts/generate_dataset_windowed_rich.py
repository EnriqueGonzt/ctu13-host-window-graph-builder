#!/usr/bin/env python3
import argparse
import pickle
from pathlib import Path
from collections import defaultdict

import numpy as np
import pandas as pd
import networkx as nx


def find_col(cols, candidates):
    low = {c.lower(): c for c in cols}
    for cand in candidates:
        if cand.lower() in low:
            return low[cand.lower()]
    return None


def is_botnet_label(x):
    s = str(x).lower()
    return int(("botnet" in s) or ("malicious" in s))


def safe_numeric(series, default=0.0):
    return pd.to_numeric(series, errors="coerce").fillna(default)


def parse_port(x):
    if pd.isna(x):
        return -1
    s = str(x).strip()
    if s == "" or s.lower() == "nan":
        return -1
    try:
        if s.lower().startswith("0x"):
            return int(s, 16)
        return int(float(s))
    except Exception:
        return -1


def parse_tos(x):
    if pd.isna(x):
        return None
    s = str(x).strip()
    if s == "" or s.lower() == "nan":
        return None
    try:
        return float(s)
    except Exception:
        return None


def clean_proto(x):
    s = str(x).strip().lower()
    if s in ("tcp", "udp", "icmp"):
        return s
    return "other"


def clean_dir(x):
    s = str(x).strip()
    if s == "<->":
        return "bidir"
    if s == "->":
        return "out"
    if s == "<-":
        return "in"
    return "unknown"


def clean_state(x):
    if pd.isna(x):
        return "missing"
    s = str(x).strip()
    if s == "" or s.lower() == "nan":
        return "missing"
    if s == "CON":
        return "CON"
    if s == "INT":
        return "INT"
    if s == "S_":
        return "S"
    if s == "S_RA":
        return "S_RA"
    if s == "FSPA_FSPA":
        return "FSPA_FSPA"
    return "other"


def detect_schema(csv_file):
    df = pd.read_csv(csv_file, nrows=5)
    cols = list(df.columns)

    schema = {
        "time": find_col(cols, ["StartTime", "stime", "start", "time"]),
        "dur": find_col(cols, ["Dur", "Duration", "dur"]),
        "proto": find_col(cols, ["Proto", "Protocol", "proto"]),
        "src": find_col(cols, ["SrcAddr", "SrcIP", "srcaddr", "src_ip"]),
        "sport": find_col(cols, ["Sport", "SrcPort", "sport", "srcport"]),
        "dir": find_col(cols, ["Dir", "Direction", "dir"]),
        "dst": find_col(cols, ["DstAddr", "DstIP", "dstaddr", "dst_ip"]),
        "dport": find_col(cols, ["Dport", "DstPort", "dstport", "dport"]),
        "state": find_col(cols, ["State", "state"]),
        "stos": find_col(cols, ["sTos", "STos", "stos"]),
        "dtos": find_col(cols, ["dTos", "DTos", "dtos"]),
        "pkts": find_col(cols, ["TotPkts", "Packets", "TotPackets", "pkts"]),
        "bytes": find_col(cols, ["TotBytes", "Bytes", "totbytes"]),
        "srcbytes": find_col(cols, ["SrcBytes", "srcbytes", "Src_Bytes"]),
        "label": find_col(cols, ["Label", "label", "class"]),
    }

    required = ["time", "src", "dst", "label"]
    missing = [k for k in required if schema[k] is None]
    if missing:
        raise RuntimeError(f"Faltan columnas obligatorias en {csv_file}: {missing}. Columnas: {cols}")

    return schema


def make_stat():
    return {
        "out_flows": 0.0,
        "in_flows": 0.0,

        "bytes_out": 0.0,
        "bytes_in": 0.0,
        "bytes_sum": 0.0,
        "bytes_sq_sum": 0.0,
        "bytes_max": 0.0,

        "pkts_out": 0.0,
        "pkts_in": 0.0,
        "pkts_sum": 0.0,
        "pkts_sq_sum": 0.0,
        "pkts_max": 0.0,

        "dur_sum": 0.0,
        "dur_sq_sum": 0.0,
        "dur_max": 0.0,

        "srcbytes_sum": 0.0,
        "srcbytes_sq_sum": 0.0,
        "srcbytes_max": 0.0,

        "dst_ports": set(),
        "src_ports": set(),

        "proto_udp": 0.0,
        "proto_tcp": 0.0,
        "proto_icmp": 0.0,
        "proto_other": 0.0,

        "dir_bidir": 0.0,
        "dir_out": 0.0,
        "dir_in": 0.0,
        "dir_unknown": 0.0,

        "dport_53": 0.0,
        "dport_80": 0.0,
        "dport_443": 0.0,
        "dport_22": 0.0,
        "dport_25": 0.0,
        "dport_3389": 0.0,
        "dport_high": 0.0,
        "dport_missing": 0.0,

        "sport_high": 0.0,
        "sport_missing": 0.0,

        "state_CON": 0.0,
        "state_INT": 0.0,
        "state_S": 0.0,
        "state_S_RA": 0.0,
        "state_FSPA_FSPA": 0.0,
        "state_other": 0.0,
        "state_missing": 0.0,

        "sTos_missing": 0.0,
        "sTos_nonzero": 0.0,
        "dTos_missing": 0.0,
        "dTos_nonzero": 0.0,

        "malicious": 0,
    }


def update_stat(st, role, dur, pkts, nbytes, srcbytes, sport, dport, proto, direction, state, stos, dtos):
    if role == "out":
        st["out_flows"] += 1.0
        st["bytes_out"] += nbytes
        st["pkts_out"] += pkts
    else:
        st["in_flows"] += 1.0
        st["bytes_in"] += nbytes
        st["pkts_in"] += pkts

    st["bytes_sum"] += nbytes
    st["bytes_sq_sum"] += nbytes * nbytes
    st["bytes_max"] = max(st["bytes_max"], nbytes)

    st["pkts_sum"] += pkts
    st["pkts_sq_sum"] += pkts * pkts
    st["pkts_max"] = max(st["pkts_max"], pkts)

    st["dur_sum"] += dur
    st["dur_sq_sum"] += dur * dur
    st["dur_max"] = max(st["dur_max"], dur)

    st["srcbytes_sum"] += srcbytes
    st["srcbytes_sq_sum"] += srcbytes * srcbytes
    st["srcbytes_max"] = max(st["srcbytes_max"], srcbytes)

    if dport >= 0:
        st["dst_ports"].add(int(dport))
    if sport >= 0:
        st["src_ports"].add(int(sport))

    if proto == "udp":
        st["proto_udp"] += 1.0
    elif proto == "tcp":
        st["proto_tcp"] += 1.0
    elif proto == "icmp":
        st["proto_icmp"] += 1.0
    else:
        st["proto_other"] += 1.0

    if direction == "bidir":
        st["dir_bidir"] += 1.0
    elif direction == "out":
        st["dir_out"] += 1.0
    elif direction == "in":
        st["dir_in"] += 1.0
    else:
        st["dir_unknown"] += 1.0

    if dport < 0:
        st["dport_missing"] += 1.0
    elif dport == 53:
        st["dport_53"] += 1.0
    elif dport == 80:
        st["dport_80"] += 1.0
    elif dport == 443:
        st["dport_443"] += 1.0
    elif dport == 22:
        st["dport_22"] += 1.0
    elif dport == 25:
        st["dport_25"] += 1.0
    elif dport == 3389:
        st["dport_3389"] += 1.0

    if dport >= 1024:
        st["dport_high"] += 1.0

    if sport < 0:
        st["sport_missing"] += 1.0
    elif sport >= 1024:
        st["sport_high"] += 1.0

    if state == "missing":
        st["state_missing"] += 1.0
    elif state == "CON":
        st["state_CON"] += 1.0
    elif state == "INT":
        st["state_INT"] += 1.0
    elif state == "S":
        st["state_S"] += 1.0
    elif state == "S_RA":
        st["state_S_RA"] += 1.0
    elif state == "FSPA_FSPA":
        st["state_FSPA_FSPA"] += 1.0
    else:
        st["state_other"] += 1.0

    if stos is None:
        st["sTos_missing"] += 1.0
    elif stos != 0.0:
        st["sTos_nonzero"] += 1.0

    if dtos is None:
        st["dTos_missing"] += 1.0
    elif dtos != 0.0:
        st["dTos_nonzero"] += 1.0


def mean_std(sum_val, sq_sum_val, n):
    if n <= 0:
        return 0.0, 0.0
    mean = sum_val / n
    var = max((sq_sum_val / n) - (mean * mean), 0.0)
    return mean, float(np.sqrt(var))


BASE_FEATURE_NAMES = [
    "flow_out_count",
    "flow_in_count",
    "flow_total_count",

    "bytes_out_sum",
    "bytes_in_sum",
    "bytes_total_sum",
    "bytes_mean",
    "bytes_std",
    "bytes_max",

    "pkts_out_sum",
    "pkts_in_sum",
    "pkts_total_sum",
    "pkts_mean",
    "pkts_std",
    "pkts_max",

    "dur_total_sum",
    "dur_mean",
    "dur_std",
    "dur_max",

    "srcbytes_sum",
    "srcbytes_mean",
    "srcbytes_std",
    "srcbytes_max",
    "srcbytes_ratio",

    "unique_dst_ports",
    "unique_src_ports",

    "proto_udp_count",
    "proto_tcp_count",
    "proto_icmp_count",
    "proto_other_count",
    "proto_udp_ratio",
    "proto_tcp_ratio",
    "proto_icmp_ratio",

    "dir_bidir_count",
    "dir_out_count",
    "dir_in_count",
    "dir_unknown_count",
    "dir_bidir_ratio",
    "dir_out_ratio",
    "dir_in_ratio",

    "dport_53_count",
    "dport_80_count",
    "dport_443_count",
    "dport_22_count",
    "dport_25_count",
    "dport_3389_count",
    "dport_high_count",
    "dport_missing_count",

    "sport_high_count",
    "sport_missing_count",

    "state_CON_count",
    "state_INT_count",
    "state_S_count",
    "state_S_RA_count",
    "state_FSPA_FSPA_count",
    "state_other_count",
    "state_missing_count",

    "sTos_missing_count",
    "sTos_nonzero_count",
    "dTos_missing_count",
    "dTos_nonzero_count",
]

CENTRAL_FEATURE_NAMES = [
    "in_degree",
    "out_degree",
    "total_degree",
    "betweenness",
    "pagerank",
    "clustering",
]


def build_row(st):
    n_out = st["out_flows"]
    n_in = st["in_flows"]
    n_total = n_out + n_in

    bytes_mean, bytes_std = mean_std(st["bytes_sum"], st["bytes_sq_sum"], n_total)
    pkts_mean, pkts_std = mean_std(st["pkts_sum"], st["pkts_sq_sum"], n_total)
    dur_mean, dur_std = mean_std(st["dur_sum"], st["dur_sq_sum"], n_total)
    srcbytes_mean, srcbytes_std = mean_std(st["srcbytes_sum"], st["srcbytes_sq_sum"], n_total)

    srcbytes_ratio = st["srcbytes_sum"] / st["bytes_sum"] if st["bytes_sum"] > 0 else 0.0

    proto_udp_ratio = st["proto_udp"] / n_total if n_total > 0 else 0.0
    proto_tcp_ratio = st["proto_tcp"] / n_total if n_total > 0 else 0.0
    proto_icmp_ratio = st["proto_icmp"] / n_total if n_total > 0 else 0.0

    dir_bidir_ratio = st["dir_bidir"] / n_total if n_total > 0 else 0.0
    dir_out_ratio = st["dir_out"] / n_total if n_total > 0 else 0.0
    dir_in_ratio = st["dir_in"] / n_total if n_total > 0 else 0.0

    return [
        n_out,
        n_in,
        n_total,

        st["bytes_out"],
        st["bytes_in"],
        st["bytes_sum"],
        bytes_mean,
        bytes_std,
        st["bytes_max"],

        st["pkts_out"],
        st["pkts_in"],
        st["pkts_sum"],
        pkts_mean,
        pkts_std,
        st["pkts_max"],

        st["dur_sum"],
        dur_mean,
        dur_std,
        st["dur_max"],

        st["srcbytes_sum"],
        srcbytes_mean,
        srcbytes_std,
        st["srcbytes_max"],
        srcbytes_ratio,

        float(len(st["dst_ports"])),
        float(len(st["src_ports"])),

        st["proto_udp"],
        st["proto_tcp"],
        st["proto_icmp"],
        st["proto_other"],
        proto_udp_ratio,
        proto_tcp_ratio,
        proto_icmp_ratio,

        st["dir_bidir"],
        st["dir_out"],
        st["dir_in"],
        st["dir_unknown"],
        dir_bidir_ratio,
        dir_out_ratio,
        dir_in_ratio,

        st["dport_53"],
        st["dport_80"],
        st["dport_443"],
        st["dport_22"],
        st["dport_25"],
        st["dport_3389"],
        st["dport_high"],
        st["dport_missing"],

        st["sport_high"],
        st["sport_missing"],

        st["state_CON"],
        st["state_INT"],
        st["state_S"],
        st["state_S_RA"],
        st["state_FSPA_FSPA"],
        st["state_other"],
        st["state_missing"],

        st["sTos_missing"],
        st["sTos_nonzero"],
        st["dTos_missing"],
        st["dTos_nonzero"],
    ]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--root", default="CTU-13-Dataset")
    ap.add_argument("--out", default="data/dataset_windowed_all13_rich.pkl")
    ap.add_argument("--window", type=int, default=3600)
    ap.add_argument("--chunksize", type=int, default=500000)
    ap.add_argument("--max-nodes", type=int, default=0)
    ap.add_argument("--betweenness-k", type=int, default=500)
    args = ap.parse_args()

    root = Path(args.root)
    files = sorted(root.glob("*/*.binetflow"))

    if not files:
        raise SystemExit(f"No encontré .binetflow en {root}")

    print("Archivos .binetflow encontrados:")
    for f in files:
        print(" -", f)

    node_stats = defaultdict(make_stat)
    edge_counts = defaultdict(int)
    scenario_by_node = {}
    window_by_node = {}

    node_id = {}
    next_id = 0

    def get_node(scenario, window, host):
        nonlocal next_id
        key = (int(scenario), int(window), str(host))
        if key not in node_id:
            node_id[key] = next_id
            scenario_by_node[next_id] = int(scenario)
            window_by_node[next_id] = int(window)
            next_id += 1
        return node_id[key]

    total_rows = 0
    total_malicious_rows = 0

    for csv_file in files:
        scenario = int(csv_file.parent.name)
        print(f"\nProcesando escenario {scenario}: {csv_file}")

        schema = detect_schema(csv_file)
        print("Schema detectado:", schema)

        usecols = [c for c in schema.values() if c is not None]
        usecols = list(dict.fromkeys(usecols))

        for chunk in pd.read_csv(csv_file, usecols=usecols, chunksize=args.chunksize, low_memory=False):
            total_rows += len(chunk)

            t = pd.to_datetime(chunk[schema["time"]], errors="coerce")
            epoch = (t.astype("int64") // 10**9)
            epoch = epoch.where(t.notna(), 0)
            windows = (epoch // args.window).astype("int64")

            src = chunk[schema["src"]].astype(str)
            dst = chunk[schema["dst"]].astype(str)

            dur = safe_numeric(chunk[schema["dur"]], 0.0) if schema["dur"] else pd.Series(np.zeros(len(chunk)))
            pkts = safe_numeric(chunk[schema["pkts"]], 0.0) if schema["pkts"] else pd.Series(np.ones(len(chunk)))
            nbytes = safe_numeric(chunk[schema["bytes"]], 0.0) if schema["bytes"] else pd.Series(np.zeros(len(chunk)))
            srcbytes = safe_numeric(chunk[schema["srcbytes"]], 0.0) if schema["srcbytes"] else pd.Series(np.zeros(len(chunk)))

            sports = chunk[schema["sport"]].map(parse_port) if schema["sport"] else pd.Series(np.full(len(chunk), -1))
            dports = chunk[schema["dport"]].map(parse_port) if schema["dport"] else pd.Series(np.full(len(chunk), -1))

            protos = chunk[schema["proto"]].map(clean_proto) if schema["proto"] else pd.Series(["other"] * len(chunk))
            dirs = chunk[schema["dir"]].map(clean_dir) if schema["dir"] else pd.Series(["unknown"] * len(chunk))
            states = chunk[schema["state"]].map(clean_state) if schema["state"] else pd.Series(["missing"] * len(chunk))

            stos_vals = chunk[schema["stos"]].map(parse_tos) if schema["stos"] else pd.Series([None] * len(chunk))
            dtos_vals = chunk[schema["dtos"]].map(parse_tos) if schema["dtos"] else pd.Series([None] * len(chunk))

            labels = chunk[schema["label"]].map(is_botnet_label)
            total_malicious_rows += int(labels.sum())

            for s_ip, d_ip, w, du, pk, by, sb, sp, dp, pr, dr, stt, sto, dto, lab in zip(
                src, dst, windows, dur, pkts, nbytes, srcbytes,
                sports, dports, protos, dirs, states, stos_vals, dtos_vals, labels
            ):
                if s_ip in ("nan", "", "-") or d_ip in ("nan", "", "-"):
                    continue

                u = get_node(scenario, w, s_ip)
                v = get_node(scenario, w, d_ip)

                update_stat(node_stats[u], "out", float(du), float(pk), float(by), float(sb),
                            int(sp), int(dp), pr, dr, stt, sto, dto)

                update_stat(node_stats[v], "in", float(du), float(pk), float(by), float(sb),
                            int(sp), int(dp), pr, dr, stt, sto, dto)

                if lab:
                    node_stats[u]["malicious"] = 1

                if u != v:
                    edge_counts[(u, v)] += 1

            print(f"  filas acumuladas={total_rows:,}, nodos={len(node_id):,}, aristas={len(edge_counts):,}")

    N0 = len(node_id)

    print("\nConstruyendo grafo completo...")
    G_full = nx.DiGraph()
    G_full.add_nodes_from(range(N0))
    for (u, v), w in edge_counts.items():
        G_full.add_edge(u, v, weight=w)

    y_full = np.zeros(N0, dtype=np.int64)
    X_stat = np.zeros((N0, len(BASE_FEATURE_NAMES)), dtype=np.float32)

    for n in range(N0):
        st = node_stats[n]
        y_full[n] = int(st["malicious"])
        X_stat[n, :] = np.array(build_row(st), dtype=np.float32)

    if args.max_nodes and N0 > args.max_nodes:
        print(f"\nAplicando recorte a max_nodes={args.max_nodes}...")
        positives = np.where(y_full == 1)[0].tolist()
        negatives = np.where(y_full == 0)[0].tolist()

        total_count_idx = BASE_FEATURE_NAMES.index("flow_total_count")
        neg_scores = [(n, X_stat[n, total_count_idx]) for n in negatives]
        neg_scores.sort(key=lambda x: x[1], reverse=True)

        remaining = max(args.max_nodes - len(positives), 0)
        selected = positives + [n for n, _ in neg_scores[:remaining]]
        selected = sorted(set(selected))

        old_to_new = {old: i for i, old in enumerate(selected)}

        G = nx.DiGraph()
        G.add_nodes_from(range(len(selected)))

        for u, v, data in G_full.edges(data=True):
            if u in old_to_new and v in old_to_new:
                G.add_edge(old_to_new[u], old_to_new[v], **data)

        X_stat = X_stat[selected]
        y = y_full[selected]
        scenarios = np.array([scenario_by_node[n] for n in selected], dtype=np.int64)
        windows_arr = np.array([window_by_node[n] for n in selected], dtype=np.int64)
    else:
        G = G_full
        y = y_full
        scenarios = np.array([scenario_by_node[n] for n in range(N0)], dtype=np.int64)
        windows_arr = np.array([window_by_node[n] for n in range(N0)], dtype=np.int64)

    print("\nCalculando centralidades...")
    N = G.number_of_nodes()

    in_deg = np.array([G.in_degree(n) for n in range(N)], dtype=np.float32)
    out_deg = np.array([G.out_degree(n) for n in range(N)], dtype=np.float32)
    total_deg = in_deg + out_deg

    UG = G.to_undirected()

    if N > 3000:
        k = min(args.betweenness_k, N)
        print(f"  Grafo grande: betweenness aproximado con k={k}")
        btw_dict = nx.betweenness_centrality(UG, k=k, seed=0, normalized=True)
    else:
        btw_dict = nx.betweenness_centrality(UG, normalized=True)

    pr_dict = nx.pagerank(G, max_iter=100, tol=1e-6)
    clust_dict = nx.clustering(UG)

    central = np.zeros((N, len(CENTRAL_FEATURE_NAMES)), dtype=np.float32)
    for n in range(N):
        central[n, 0] = in_deg[n]
        central[n, 1] = out_deg[n]
        central[n, 2] = total_deg[n]
        central[n, 3] = float(btw_dict.get(n, 0.0))
        central[n, 4] = float(pr_dict.get(n, 0.0))
        central[n, 5] = float(clust_dict.get(n, 0.0))

    X = np.hstack([X_stat, central]).astype(np.float32)
    feature_names = BASE_FEATURE_NAMES + CENTRAL_FEATURE_NAMES

    data = {
        "G": G,
        "X": X,
        "y": y.astype(np.int64),
        "scenarios": scenarios,
        "windows": windows_arr,
        "feature_names": feature_names,
        "description": "CTU-13 host-window rich feature dataset. No raw IPs, no Label leakage, no absolute StartTime as feature.",
    }

    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)

    with open(out, "wb") as f:
        pickle.dump(data, f, protocol=pickle.HIGHEST_PROTOCOL)

    print("\n====================================================")
    print("Dataset generado:", out)
    print("Filas leídas:", f"{total_rows:,}")
    print("Filas con etiqueta botnet/malicious:", f"{total_malicious_rows:,}")
    print("Nodos:", G.number_of_nodes())
    print("Aristas:", G.number_of_edges())
    print("Features:", X.shape[1])
    print("Positivos:", int(y.sum()))
    print("Negativos:", int((y == 0).sum()))
    print("Escenarios:", sorted(set(scenarios.tolist())))
    print("\nFeature names:")
    for i, name in enumerate(feature_names):
        print(f"{i:02d}: {name}")


if __name__ == "__main__":
    main()
