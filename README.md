# AutoPYara Backend

**The JVM engine behind [AutoPYara](https://github.com/Botacin-s-Lab/AutoPYaraPyPI) — byte n-gram extraction, Bloom-filter isolation, biclustering, and YARA rule synthesis.**

[![Java CI with Maven](https://github.com/Botacin-s-Lab/AutoPYaraBackend/actions/workflows/build.yml/badge.svg)](https://github.com/Botacin-s-Lab/AutoPYaraBackend/actions/workflows/build.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Java 11+](https://img.shields.io/badge/java-11%2B-orange.svg)](#building-from-source)

---

## What this is

This repository builds `AutoYara.jar` — the Java backend that does the computationally heavy part of AutoPYara: extracting byte n-grams from malware samples, filtering them against benign/malicious counting Bloom filters, biclustering the surviving candidates, and assembling the result into YARA rules.

It is **not** used directly by end users. It is consumed by the Python package [`autopyara`](https://pypi.org/project/autopyara/), which embeds the built jar and drives it over [JPype](https://jpype.readthedocs.io/).

```
┌──────────────────────────────┐         ┌────────────────────────────────────┐
│ AutoPYaraBackend (this repo) │         │  AutoPYaraPyPI (Python package)    │
│                              │  jar    │                                    │
│  Java 11 · Maven             │────────▶│  autopyara/jars/AutoYara.jar       │
│  mvn package → shaded jar    │         │  driven via JPype                  │
│                              │         │  ships to PyPI as `autopyara`      │
└──────────────────────────────┘         └────────────────────────────────────┘
```

The split matters: the **ssdeep + DBSCAN pre-clustering** lives on the Python side, and its output (`predictorLabels`) is handed back into this Java code, which uses it to seed robust centroid estimation. See [The augmented pipeline](#the-augmented-pipeline).

## Provenance and credits

This project builds on **AutoYara** (Raff et al., *"Automatic Yara Rule Generation Using Biclustering"*, AISec 2020) — visible in the retained package namespace `edu.lps.acs.ml.autoyara` and the `AutoYara` Maven artifact ID. The original CLI (`AutoYaraCluster`), Bloom filter machinery, and biclustering-based rule construction derive from that work.

Contributions original to this repository are principally:

- `AutoYaraPython` — a dedicated JPype-facing API and result-dictionary output
- The `clustering/` package — an abstraction over clustering strategies
- `AugmentedKMeansClusterer` / `AugmentedKMeansSoftClusterer` — robust, predictor-label-seeded centroid estimation
- Soft (fuzzy-membership) clustering variants and the `PYara` candidate-selection heuristic

Third-party dependencies:

| Dependency | Purpose |
|---|---|
| JSAT (`com.github.EdwardRaff`) | Linear algebra, clustering, spectral co-clustering |
| KiloGrams (`com.github.gnat-n`) | Large-scale byte n-gram extraction |
| `me.tongfei:progressbar` | Terminal progress bars |
| `dk.brics:automaton` | Automaton/regex primitives |

> **Note for maintainers:** the `LICENSE` here is MIT © Marcus Botacin. Because this is a derivative of upstream AutoYara, the upstream repository link, its license, and its copyright notice should be explicitly cited in this file and retained per that license's terms. Worth confirming before any formal (e.g. artifact-evaluation or archival) release.

## Repository layout

```
src/main/java/edu/lps/acs/ml/autoyara/
├── AutoYaraCluster.java          # Original CLI entry point (jar Main-Class)
├── AutoYaraPython.java           # JPype-facing API — the only class Python should touch
├── Bytes2Bloom.java              # Trains counting Bloom filters from a corpus
├── CountingBloom.java            # Counting Bloom filter implementation
├── CountingBloomInfo.java        # Filter metadata (size, false-positive rate, n-gram size)
├── SigCandidate.java             # A candidate n-gram signature and its statistics
├── YaraRuleContainerConjunctive.java   # Assembles/serializes YARA rules; holds outputDictionary
├── SpectralCoClusteringVBMM.java # Spectral co-clustering with a variational Bayes mixture
├── MemoryMonitor.java            # Heap usage tracking
└── clustering/
    ├── ClusteringAlgorithm.java          # Abstract base: hard + soft assignment helpers
    ├── BiclusteringPipeline.java         # Pipeline interface
    ├── BiclusteringOutput.java           # Result holder (assignments, k_used)
    ├── SpectralCoClusterPipeline.java    # Biclustering pipeline w/ normalization modes
    ├── VBGMMClusterer.java               # Variational Bayes GMM (infers k)
    ├── KMeansClusterer.java              # Standard k-means
    ├── KMeansSoftClusterer.java          # Fuzzy k-means
    ├── RandomClusterer.java              # Random baseline
    ├── AugmentedKMeansClusterer.java     # ★ Robust centroids via CRDEST + predictor labels
    └── AugmentedKMeansSoftClusterer.java # ★ Fuzzy variant of the above

src/main/java-templates/.../Version.java  # Templated — build version/timestamp injected by Maven
```

## Clustering algorithms

Selected by setting the `clusterAlg` string on `AutoYaraPython`. An unrecognized value silently falls back to `VBGMM`.

| `clusterAlg` | Implementation | Needs `k` | Needs `predictorLabels` | Assignment |
|---|---|:--:|:--:|---|
| `VBGMM` *(default)* | `VBGMMClusterer` | – | – | Hard; infers *k* |
| `KMeans` | `KMeansClusterer` | ✔ | – | Hard |
| `KMeansSoft` | `KMeansSoftClusterer` | ✔ | – | Fuzzy |
| `Random` | `RandomClusterer` | ✔ | – | Hard (baseline) |
| `AugmentedKMeansDBSCAN` | `AugmentedKMeansClusterer` | ✔ | ✔ | Hard |
| `AugmentedKMeansVT` | `AugmentedKMeansClusterer` | ✔ | ✔ | Hard |
| `AugmentedKMeansDBSCANSoft` | `AugmentedKMeansSoftClusterer` | ✔ | ✔ | Fuzzy |
| `AugmentedKMeansVTSoft` | `AugmentedKMeansSoftClusterer` | ✔ | ✔ | Fuzzy |

Biclustering pipeline, via `biclusterPipelineAlg`:

| Value | Input normalization |
|---|---|
| `SpectralCoCluster` *(default)* | Bistochastization |
| `SpectralCoClusterScale` | Scale |

## The augmented pipeline

The `AugmentedKMeans*` clusterers are the reason this backend is split across two languages.

1. **Python side** (`autopyara.augmented_predictor.DBSCAN_SSDEEP`) fuzzy-hashes each input sample with ssdeep, builds a pairwise distance matrix, and runs DBSCAN to produce a label per sample.
2. Those labels are pushed into this backend as `predictorLabels`, along with `k = |unique labels|`.
3. **Java side** (`AugmentedKMeansClusterer`) uses the labels to partition samples into groups `Yᵢ`, then estimates each cluster centroid **coordinate-by-coordinate** using **CRDEST**, a corruption-robust estimator:
   - randomly split the coordinate's values into halves `X₁`, `X₂`
   - find the shortest interval containing `m(1 − 5α)` points of `X₁`
   - average the `X₂` points falling inside that interval (median fallback if empty)
   - sweep the corruption parameter `α` over `0.01 … 0.15` and keep the centroid set with the lowest total assignment cost
4. Samples are then assigned to the nearest centroid (squared Euclidean), and the biclustering pipeline proceeds as usual.

The intent is centroids that resist outliers and noise in the byte-signature feature space better than plain k-means, while borrowing family structure from the fuzzy-hash clustering.

## Building from source

**Prerequisites:** JDK 11 or newer (CI uses Temurin 17) and Maven.

```bash
mvn -B package
```

Output: `target/AutoYara-1.0-SNAPSHOT.jar` — a **shaded fat jar** (`maven-shade-plugin`, `minimizeJar=true`) bundling all dependencies, with `Main-Class: edu.lps.acs.ml.autoyara.AutoYaraCluster`.

Some dependencies resolve through [JitPack](https://jitpack.io), declared as a repository in `pom.xml`; the first build will reach out to it.

## Usage

### As the backend for the Python package (primary path)

Normally you don't invoke this jar yourself — install the Python package instead:

```bash
pip install autopyara
```

To test a locally built jar against the Python package, copy it over `autopyara/jars/AutoYara.jar` in your installed/checked-out copy of the package. (The package also honours an `AUTOPYARA_JAR` environment variable, but only as a *fallback* when no jar is bundled at that path — it does not override a jar that is already present.)

### Command line

```bash
java -jar target/AutoYara-1.0-SNAPSHOT.jar \
    --input-dir  /path/to/malware/samples \
    --benign     /path/to/benign-bytes \
    --malicious  /path/to/malicious-bytes \
    --out        rules.yar \
    --print-rules
```

Selected options (see `AutoYaraCluster` for the full set):

| Option | Meaning |
|---|---|
| `-i`, `--input-dir` | **Required.** Directory of files to n-gram |
| `-b`, `--benign` | Directory of benign Bloom filters |
| `-m`, `--malicious` | Directory of malicious Bloom filters |
| `-o`, `--out` | Output file/directory for generated rules |
| `-fpb`, `--false-pos-benign` | Max benign false-positive rate for a signature |
| `-fpm`, `--false-pos-malicious` | Max malicious false-positive rate for a signature |
| `-msr`, `--min-support-ratio` | Min fraction of input files an n-gram must cover |
| `-msc`, `--min-support-count` | Min number of files a signature must catch |
| `-me`, `--min-entropy` | Min entropy for an n-gram to be considered |
| `-mfs`, `--max-filter-size` | Max filter size (larger = better rules, more RAM) |
| `-k`, `--to-keep` | Number of n-gram candidates kept at each step |
| `--target-coverage` | Sub-rules to hit per example (larger ⇒ larger rules) |
| `--save-all-rules`, `--print-rules`, `--silent` | Output behavior |

### Training Bloom filters

`Bytes2Bloom` builds the counting Bloom filters that the rule generator filters candidates against:

```bash
java -cp target/AutoYara-1.0-SNAPSHOT.jar \
    edu.lps.acs.ml.autoyara.Bytes2Bloom \
    -i /corpus/benign -o /output/benign-bytes
```

Configurable fields include `gramSizes`, `filterSize`, `false_pos`, and `tooKeep`. The Python package exposes this as `AutoPYara.train()`.

## The Java ↔ Python bridge

`AutoYaraPython extends AutoYaraCluster` and is documented in-source as the **only** class JPype should touch — deliberately, to avoid coupling the Python layer to internals.

Typical call sequence from Python:

```python
cluster = jpype.JPackage("edu.lps.acs.ml.autoyara").AutoYaraPython()
# ... set fields ...
cluster.findBestRulePipelineInit()   # load inputs, extract candidates
result = cluster.pythonRun()         # returns outputDictionary
cluster.resetYaraState()             # clear state before reuse
```

Fields set by the Python layer:

| Field | Declared in | Purpose |
|---|---|---|
| `inDir` | `AutoYaraCluster` | `List<File>` of input samples |
| `benign_bloom_dir` / `malicious_bloom_dir` | `AutoYaraCluster` | Bloom filter directories |
| `max_filter_size` | `AutoYaraCluster` | Filter size cap (RAM/quality tradeoff) |
| `clusterAlg` / `biclusterPipelineAlg` | `AutoYaraPython` | Algorithm selection |
| `selectionHeuristic` | `AutoYaraPython` | `"AutoYara"` or `"PYara"` candidate selection |
| `biclusterFeaturePruneCoverage` | `AutoYaraPython` | Prune bicluster features below this coverage (default `0.5`) |
| `k` | `AutoYaraPython` | Cluster count; `≤ 0` defaults to `0.3 × n_samples` |
| `predictorLabels` | `AutoYaraPython` | Per-sample labels required by `AugmentedKMeans*` |
| `name`, `out_dir` | `AutoYaraPython` | Rule naming and optional output directory |

Read back from Java: `targets` (resolved input paths) and the `pythonRun()` result dictionary, which carries `rule_string`, `k_clusters`, `strings`, `file_count`, `total_files`, `TP`, `TP_total`, `conditions_min`, `conditions_max`, `gram_size`, and `byte_candidate_count`.

`pythonRun()` returns `null` if no rule satisfying the configured constraints could be built.

## Continuous integration and releases

[`.github/workflows/build.yml`](.github/workflows/build.yml) has three jobs:

| Job | When it runs | What it does |
|---|---|---|
| `gate` | Every push to `main`, and manual dispatch | Decides whether a release was requested |
| `build` | Every push to `main` | `mvn -B package` on Temurin JDK 17; uploads the jar as a workflow artifact |
| `release` | Only when `gate` says so | Tags the commit, creates a GitHub Release, attaches the jar |

**Every push compiles**, so breakage is caught immediately. A **release is only cut when you ask for one**, in either of two ways:

- Push a commit whose **subject line** contains `NewVersion` or `New version` (case-insensitive; both spellings are accepted).
- Run the workflow manually from the Actions tab with the **`release`** input checked.

Only the first line of the commit message is examined — a commit *body* that merely mentions the phrase will not trigger a release.

Releases are tagged `yyyyMMddHHmmss` and carry `AutoYara-1.0-SNAPSHOT-<timestamp>.jar`, downloadable from the [Releases page](https://github.com/Botacin-s-Lab/AutoPYaraBackend/releases). The release notes record the **commit SHA** the jar was built from, so any published jar can be traced back to its source.

> **Note:** the jar is not automatically propagated into [AutoPYaraPyPI](https://github.com/Botacin-s-Lab/AutoPYaraPyPI) — updating `autopyara/jars/AutoYara.jar` there is currently a manual step. (An earlier version of this workflow attempted a cross-repository push to a repository named `AutoPyYara`, which no longer exists; that step failed on every run and has been removed.)

## Known limitations

- **Nondeterministic output.** `AugmentedKMeansClusterer.runCRDEST()` uses an unseeded `new Random()` for its `X₁`/`X₂` partition (`AugmentedKMeansClusterer.java:122`); a `setSeed(0L)` call sits commented out on the next line. `RandomClusterer` is likewise unseeded. Repeated runs on identical inputs can therefore produce different centroids and different rules. Exposing a configurable seed would make results reproducible.
- **No automated tests.** There is no test suite; the `test` file at the repository root is an unrelated 5-byte stray file.
- **Version is fixed at `1.0-SNAPSHOT`.** Releases are distinguished only by their timestamp tag, so a jar's *filename* does not identify its source commit. The release notes record the commit SHA, which covers traceability in practice, but adopting real semantic versions in `pom.xml` would be cleaner.

## License

MIT — see [LICENSE](LICENSE). See [Provenance and credits](#provenance-and-credits) regarding upstream attribution.
