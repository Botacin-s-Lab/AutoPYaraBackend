package edu.lps.acs.ml.autoyara;

import com.beust.jcommander.Parameter;
import edu.lps.acs.ml.autoyara.clustering.*;
import edu.lps.acs.ml.ngram3.utils.GZIPHelper;
import jsat.SimpleDataSet;
import jsat.classifiers.DataPoint;
import jsat.clustering.biclustering.SpectralCoClustering;
import jsat.linear.*;
import jsat.math.OnLineStatistics;
import jsat.utils.IntList;
import jsat.utils.concurrent.AtomicDouble;

import java.io.*;
import java.nio.file.FileVisitOption;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.*;
import java.util.concurrent.ConcurrentSkipListSet;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.stream.Collectors;
import java.util.stream.IntStream;

/**
 *  DOCUMENTATION
 *
 *  ABOUT
 *      This class serves to run AutoYara given a python interface. In the future, you should NOT
 *      access any other classes when using jpype. This is to prevent uncessary coupling.
 *
 *  EXAMPLE
 *      Without Pipeline
 *      > input training files
 *      > build bloom files
 *      > pass new files
 *      > generate candidate, cluster, refine rules
 *      > done
 *
 *      With Pipeline
 *      > input files
 *      > create byte candidates (done on java backend)
 *      > return to python for byte candidate further processing
 *      > python resumes the pipeline and passes in additional information
 *      > start byte candidate clustering in java (done on java backend)
 *      > build yara rule from clusters
 *      > done
 */

public class AutoYaraPython extends AutoYaraCluster {
    private final Bytes2Bloom myBloom;

    // These members MUST be public. Otherwise JPype cannot access them without setters/getters
    @Parameter(names = "--clusterAlg", description = "Clustering algorithm to use")
    public String clusterAlg = "VBGMM";

    @Parameter(names = "--biclusterPipelineAlg", description = "the biclustering pipeline to use")
    public String biclusterPipelineAlg = "SpectralCoCluster";

    @Parameter(names = "--filterAlg", description = "N-Gram candidate filtering algorithm to use")
    public String filterAlg = "AutoYara";

    @Parameter(names = "--extractionAlg", description = "N-Gram extraction algorithm to use")
    public String extractionAlg = "AutoYara";

    private boolean generateName = true; // will be auto set to true or false depending on if the name is provided or not
    public String name = "";
    public String out_dir;

    // These parameters are optional, but are necessary for some clustering algorithms
    public int[] predictorLabels; // required by augmented kmeans
    public int k = 0; // required by kmeans, random, and augmented kmeans, 0 or less will automatically set it to # samples * 0.3

    // We define these parameters here to make it simple to resume (some processes need to be injected w/ python code)
    public SortedSet<Integer> bloomSizes;
    Map<Integer, CountingBloom> ben_blooms;
    Map<Integer, CountingBloom> mal_blooms;
    public List<Path> targets;

    public Collection<YaraRuleContainerConjunctive> best_rule = new ArrayList<>();
    AtomicDouble best_rule_coverage = new AtomicDouble(0);
    AtomicBoolean meets_min_desired_coverage = new AtomicBoolean(false);
    AtomicInteger best_rule_gram_size = new AtomicInteger(0);

    // it's wasteful to have to recompute the byte candidates on the same file directory for every clustering algorithm
    // since it's the same every time caching skips byte extraction if the solution already exist
    // this makes it so you can run multiple clustering algorithms on a single malware family without having to recompute
    // the final byte candidates for each one, making evaluation fast
    public boolean cacheByteCandidates = true;
    private Map<Integer, List<SigCandidate>> finalCandidatesCache = new HashMap<>();
    private List<File> cachedDir;

    // the AutoYara selection heuristic encourages overfitting
    // since good 8-grams are rarer, we may occasionally get 1-2 candidates, leading to the heuristic skipping bicluster algorithms
    // and producing one large bicluster, which the selection heuristic is biased towards
    // it does not help that 8-grams usually score higher in coverage TP and outcompetes larger n-grams, leading to worse FP rates
    public String selectionHeuristic = "PYara"; // "AutoYara", "PYara"
    public boolean useBackupCoClustering = false; // for experiments, we don't use this, for the real world, we do use it
    public double biclusterFeaturePruneCoverage = 0.5; // prune biclusters features that don't cover this many % of files

    public AutoYaraPython() {
        // we copy AutoYaraCluster + all of its parameters
        // in future iterations we will slowly migrate dependency only to AutoYaraPython, so AutoYaraCluster will become obsolete
        super();
        myBloom = new Bytes2Bloom();
    }

    public void resetYaraState() {
        this.generateName = true; // will be auto set to true or false depending on if the name is provided or not
        this.name = "";
        this.out_dir = "";
        this.out_file = null;

        this.predictorLabels = null; // required by augmented kmeans
        this.k = 0; // required by kmeans, random, and augmented kmeans, 0 or less will automatically set it to # samples * 0.3

        // We define these parameters here to make it simple to resume (some processes need to be injected w/ python code)
        this.bloomSizes = null;
        this.ben_blooms = null;
        this.mal_blooms = null;
        this.targets = null;

        this.best_rule = new ArrayList<>();
        this.best_rule_coverage = new AtomicDouble(0);
        this.meets_min_desired_coverage = new AtomicBoolean(false);
        this.best_rule_gram_size = new AtomicInteger(0);

        if (!cacheByteCandidates)
            finalCandidatesCache.clear();
    }

    /**
     * Build bloom files from corpus
     *
     * the bloom files will contain the most frequent n-grams from both malicious & benign datasets
     * we don't want to use these n-grams because they're too commonly seen, so the bloom files will filter out
     * most candidates
     */
    public void buildBloomFiles() throws IOException {
        myBloom.run();
    }

    /**
     * Create a list of good n-gram candidates
     *
     * Scans all files in the specified directory, generates n-grams of specified size, and filter candidates out
     * in multiple stages.
     */
    public List<HashMap<String, Object>> buildCandidateSet(File in_dir, int gram_size, File ben_blooms_dir, File mal_blooms_dir)
            throws IOException
    {
        Map<Integer, CountingBloom> ben_blooms = AutoYaraCluster.collectBloomFilters(ben_blooms_dir);
        Map<Integer, CountingBloom> mal_blooms = AutoYaraCluster.collectBloomFilters(mal_blooms_dir);

        List<SigCandidate> final_candidates = AutoYaraCluster.buildCandidateSet(targets, gram_size, ben_blooms, mal_blooms, this.max_filter_size, toKeep, silent, Math.max(false_pos_b, false_pos_m));

        // Convert SigCandidate objects to HashMaps to be python friendly
        List<HashMap<String, Object>> candidateDicts = new ArrayList<>();
        for (SigCandidate candidate : final_candidates) {
            candidateDicts.add(candidate.ToPythonDict());
        }

        return candidateDicts;
    }

    protected BiclusteringOutput runCoclusterAlg(SimpleDataSet sigDataset)
    {
        // it doesn't matter how we implement the algorithm as long as we update the rows and cols
        ClusteringAlgorithm clusterer;
        BiclusteringPipeline pipeline;
        BiclusteringOutput out;

        if (this.generateName) {
            this.name += "_" + this.biclusterPipelineAlg;
            this.name += "_" + this.clusterAlg;
        }

        // assumption: roughly 30% of any dataset are malware variants
        // hence we will have a k value of 30% of the dataset
        // k will be used by clustering algorithms that require it as a hyperparameter

        // if k is set to 0 or less, AutoYaraPython will automatically replace it
        int selectedK = k;

        if (selectedK <= 0)
            selectedK = (sigDataset.size() * 3) / 10;

        // this is to cover an edge case where k could still be 0 or less
        if (selectedK <= 0)
            selectedK = 1;

        if (this.clusterAlg.equals("VBGMM")) {
            // System.out.println("Clusterer: using VBGMM");
            clusterer = new VBGMMClusterer();
        } else if (this.clusterAlg.equals("KMeans")) {
            // System.out.println("Clusterer: using KMeans with k " + selectedK);
            clusterer = new KMeansClusterer(selectedK);

            if (this.generateName)
                this.name += "_k" + selectedK;
        } else if (this.clusterAlg.equals("Random")) {
            // System.out.println("Clusterer: using Random with k " + selectedK);
            clusterer = new RandomClusterer(selectedK);

            if (this.generateName)
                this.name += "_k" + selectedK;
        } else if (this.clusterAlg.equals("AugmentedKMeansDBSCAN") || this.clusterAlg.equals("AugmentedKMeansVT")) {
            // System.out.println("Clusterer: using AugmentedKMeans with k " + selectedK);
            clusterer = new AugmentedKMeansClusterer(selectedK);

            if (this.generateName)
                this.name += "_k" + selectedK;
        } else if (this.clusterAlg.equals("AugmentedKMeansDBSCANSoft") || this.clusterAlg.equals("AugmentedKMeansVTSoft")) {
            // System.out.println("Clusterer: using AugmentedKMeans with k " + selectedK);
            clusterer = new AugmentedKMeansSoftClusterer(selectedK);

            if (this.generateName)
                this.name += "_k" + selectedK;
        } else {
            // System.out.println("Cluster algorithm " + this.clusterAlg + " not found. Defaulting to VBGMM clusterer.");
            // System.out.println("Clusterer: using VBGMM");
            clusterer = new VBGMMClusterer();
        }

        if (this.biclusterPipelineAlg.equals("SpectralCoCluster")) {
            SpectralCoClusterPipeline bc = new SpectralCoClusterPipeline(selectedK);
            bc.inputNormalization = SpectralCoClustering.InputNormalization.BISTOCHASTIZATION;
            // System.out.println("Biclustering: using SpectralCoCluster with bistochastic normalization");
            out = bc.bicluster(sigDataset, clusterer, this.predictorLabels);
        } else if (this.biclusterPipelineAlg.equals("SpectralCoClusterScale")) {
            SpectralCoClusterPipeline bc = new SpectralCoClusterPipeline(selectedK);
            bc.inputNormalization = SpectralCoClustering.InputNormalization.SCALE;
            // System.out.println("Biclustering: using SpectralCoCluster with scale normalization");
            out = bc.bicluster(sigDataset, clusterer, this.predictorLabels);
        } else {
            // System.out.println("Bicluster algorithm " + this.biclusterPipelineAlg + " not found. Defaulting to SpectralCoClustering with Scale normalization.");

            SpectralCoClusterPipeline bc = new SpectralCoClusterPipeline(selectedK);
            bc.inputNormalization = SpectralCoClustering.InputNormalization.SCALE;
            out = bc.bicluster(sigDataset, clusterer, this.predictorLabels);
        }

        if (this.generateName)
            this.generateName = false;
//        SpectralCoClustering bc = new SpectralCoClustering();
//        bc.setBaseClusterAlgo(new VBGMM());
//        bc.bicluster(sigDataset, true, rows, cols);
//        int min_pts = 15;
//        while(rows.isEmpty() && min_pts > 3)
//        {
//            System.out.println("trying " + min_pts);
//            bc.setBaseClusterAlgo(new HDBSCAN(min_pts--));
//            bc.bicluster(sigDataset, true, rows, cols);
//        }

        return out;
    }

    public YaraRuleContainerConjunctive buildRule2(List<SigCandidate> finalCandidates, List<Path> targets, Set<Integer> rows_covered, int gram_size, Set<Integer> alreadyFailedOn)
    {
        // stage 1: initialize variables and empty containers
        int D = finalCandidates.size(); // number of n-gram candidates/features
        int N = targets.size(); // number of files in the corpus

        if (this.selectionHeuristic.equals("AutoYara")) {
            if (this.generateName) {
                this.name += "_" + this.biclusterPipelineAlg;
                this.name += "_" + this.clusterAlg;
                this.name += "_" + "AutoYaraHeuristic";
            }
            return buildRule(finalCandidates, targets, rows_covered, this.name, SpectralCoClustering.InputNormalization.BISTOCHASTIZATION, gram_size, alreadyFailedOn);
        }

        YaraRuleContainerConjunctive yara = new YaraRuleContainerConjunctive(N, this.name); // initialize a new yara container
        yara.outputDictionary.put("k_clusters", 0);
        yara.outputDictionary.put("byte_candidate_count", D);
        yara.outputDictionary.put("file_count", N);

        if(D <= 1) // not enough candidates, we need at least 2 features
            return yara;
        // System.out.println("We have " +  D + " potential features");
        // Lets build a dataset object representing the files and which signatures (features) occured in each sample

        List<Vec> dataRep = new ArrayList<>();
        for(int i = 0; i < N; i++)
            dataRep.add(new SparseVector(D, 4));

        // stage 2: populate the containers with data given the features and files
        for(int d = 0; d < D; d++)
            for(int i : finalCandidates.get(d).coverage)
                dataRep.get(i).set(d, 1.0); // populate the matrix with 1s and 0s, where 1 means feature d exists in file i

        SimpleDataSet sigDataset = new SimpleDataSet(dataRep.stream().map(v->new DataPoint(v)).collect(Collectors.toList()));
        // note: sigDataset is in the same order as targets

        List<Set<Integer>> conjunctionSet = new ArrayList<>();
        //
        int min_rows = 5; // we need at least 5 files covered in a cluster, this will lower later if the clustering alg can't reach the req
        int min_features = 5;  // we need at least 5 features that cover 50% of the files or more, this will be lowered later if needed
        List<List<Integer>> row_clusters = new ArrayList<>();
        List<List<Integer>> col_clusters = new ArrayList<>();

        // stage 3: given matrix sigDataset, bicluster it
        BiclusteringOutput out = runCoclusterAlg(sigDataset);
        if (out == null)
            return null;

        col_clusters.addAll(out.columnAssignments);
        row_clusters.addAll(out.rowAssignments);

        yara.outputDictionary.put("k_clusters", out.k_used);
        //System.out.println("got " + out.columnAssignments.size() + " biclusters!");

        if(this.useBackupCoClustering && !alreadyFailedOn.contains(gram_size) && (row_clusters.isEmpty() || col_clusters.isEmpty()))
        {
            // For evaluation reasons, we don't attempt to use getCoClusteringH, we want to only run the algorithm we
            // picked. If it fails, then it should return nothing, not revert to a backup behavior, doing this
            // makes it harder to evaluate results since we don't know how much each algorithm relies on the backup

            alreadyFailedOn.add(gram_size);
            row_clusters.clear();
            col_clusters.clear();
            try
            {
                getCoClusteringH(sigDataset, row_clusters, col_clusters);
            }
            catch(Exception ex2)
            {
                //we give up
                row_clusters.clear();
                col_clusters.clear();
            }
        }

        // stage 4: acquire max_row_size_seen, max_features_seen, min_rows, min_features, feature_counts_all
        int max_row_size_seen = row_clusters.stream().mapToInt(r->r.size()).max().orElse(1); // what was the most files a feature covered?
        // if the best row clusters were too small, we lower expectations
        if(max_row_size_seen < min_rows)
            min_rows = max_row_size_seen;
        List<int[]> feature_counts_all = new ArrayList<>();

        // in order to know the true minimum count, we need to first perform a
        // filtering based on the counts, because we will perform a filtering
        // later. So lets collect this information now

        for(List<Integer> row_c : row_clusters)
        {
            int[] feature_counts = new int[D]; // create a list of all features and tally them up per file involved in a cluster
            for(int i: row_c)
                for(IndexValue iv : sigDataset.getDataPoint(i).getNumericalValues())
                    feature_counts[iv.getIndex()]++;
            feature_counts_all.add(feature_counts);
        }

        // how many features within a bicluster had 50% coverage or more?
        // of those, which cluster had the most features with 50% coverage?
        int max_features_seen = IntStream.range(0, row_clusters.size()).map(c->
        {
            int C_size = row_clusters.get(c).size();
            int[] feature_counts = feature_counts_all.get(c);
            return (int)col_clusters.get(c).stream().filter(j->feature_counts[j] >= this.biclusterFeaturePruneCoverage*C_size).count();
        }).max().orElse(1);

        // min features is "we need X many features that cover 50%+ of the samples in this bicluster"
        if(max_features_seen < min_features) // if the best cluster didn't hit the expectations, lower it
            min_features = Math.max(max_features_seen-1, 1);

        // stage 5: for each good cluster, perform statistics to build the smallest conjunction set that also has good coverage
        for (int c = 0; c < row_clusters.size(); c++)
        {
            int C_size = row_clusters.get(c).size();

            //System.out.println("\t" + out.rowAssignments.get(c).size() + " x " + out.columnAssignments.get(c).size());

            if(C_size < min_rows) {// pick only clusters that cover a lot of files
                //System.out.println("\tfew files! " + C_size + " < " + min_rows);
                continue;
            }
            int[] feature_counts = feature_counts_all.get(c);

            //First, lets remove obvious non-starters. You need to appear in at least half the files in your cluster
            Set<Integer> selected_features = new HashSet<>(col_clusters.get(c));

            //We are only going to consider features that occur in >= X% of this cluster
            selected_features.removeIf(j-> feature_counts[j] < this.biclusterFeaturePruneCoverage*C_size);

            //System.out.println("\thas " + selected_features.size() + " good features!");
            if(selected_features.size() < min_features) {
                //System.out.println("\tfew features! " + selected_features.size() + " < " + min_features);
                continue;
            }

            conjunctionSet.add(selected_features);

            //how many files have at least X of these features?
            List<Integer> file_occurance_counts = new ArrayList<>();
            rows_covered.addAll(row_clusters.get(c));
            for(int i : row_clusters.get(c))
            {
                int nnz_in_bic = 0;
                for(IndexValue iv : dataRep.get(i))
                    if(selected_features.contains(iv.getIndex()) && iv.getValue() > 0)
                        nnz_in_bic++;
                file_occurance_counts.add(nnz_in_bic);
            }

            Collections.sort(file_occurance_counts);
            OnLineStatistics right_portion = new OnLineStatistics();
            for(int count : file_occurance_counts)
                right_portion.add(count);

            OnLineStatistics left_portion = new OnLineStatistics();
            double min_score = Double.POSITIVE_INFINITY;
            int indx = 0;
            for(int i = 0; i < file_occurance_counts.size()-1; i++)
            {
                int count_i = file_occurance_counts.get(i);
                left_portion.add(count_i, 1.0);
                right_portion.remove(count_i, 1.0);
                //same value check, keep shifting while the value stays the same
                while(i < file_occurance_counts.size()-1 && count_i == file_occurance_counts.get(i+1))
                {
                    i++;
                    left_portion.add(count_i, 1.0);
                    right_portion.remove(count_i, 1.0);
                }


                double cur_score = left_portion.getVarance()*left_portion.getSumOfWeights()
                        + right_portion.getVarance() * right_portion.getSumOfWeights();

                if(cur_score < min_score)
                {
                    indx = i;
                    min_score = cur_score;
                }
            }


            int count_min = file_occurance_counts.get(Math.min(indx+1, file_occurance_counts.size()-1));

            //System.out.println("\tadded condition: " + count_min + " of " + selected_features.size() + " selected features");
            yara.addSignature(count_min, selected_features.stream().map(i->finalCandidates.get(i)).collect(Collectors.toSet()));

        }
        return yara;
    }

    public List<String> getPathsPython() {
        List<String> output = new ArrayList<String>();
        for (Path p : this.targets) {
            output.add(p.toString());
        }
        return output;
    }

    private void initializeOutputFile() {
        // no name specified? generate a name for the YARA rule
        if (this.name == null || this.name.trim().isEmpty()) {
            this.generateName = true; // if this is true, the entire pipeline will append information to the rule name
            this.name = inDir.get(0).getName();
        } else {
            this.generateName = false;
        }
    }

    private SortedSet<Integer> collectBloomSizes() throws IOException {
        SortedSet<Integer> bloomSizes = new ConcurrentSkipListSet<>((a, b) -> b.compareTo(a));
        collectBloomSizes(bloomSizes, benign_bloom_dir, malicious_bloom_dir);
        return bloomSizes;
    }

    public void findBestRulePipelineInit() throws IOException {
        initializeOutputFile();

        this.bloomSizes = collectBloomSizes();
        this.ben_blooms = collectBloomFilters(benign_bloom_dir);
        this.mal_blooms = collectBloomFilters(malicious_bloom_dir);
        this.targets = AutoYaraPython.getAllChildrenFiles(inDir);
        if (!inDir.equals(cachedDir)) {
            cachedDir = inDir;
            finalCandidatesCache.clear();
        }

        this.best_rule = new ArrayList<>();
        this.best_rule_coverage = new AtomicDouble(0);
        /**
         * Whether or not we meet the goal of having at least 5 terms/features
         * in conjunctions
         */
        this.meets_min_desired_coverage = new AtomicBoolean(false);
        this.best_rule_gram_size = new AtomicInteger(0);
    }

    /**
     *
     * @param header A string to add to the begining of the comment for the results
     * @param evalDirs the list of directories to perform evaluations on
     * @param yara the yara rule to evaluate, for which we will add comments to the Yara rule with the rules on each directory
     * @return the match rate against all files in the given directories
     */
    public double addMatchEval(String header, String dictHeader, List<File> evalDirs, YaraRuleContainerConjunctive yara) {
        //Lets check against false positive directories to make sure all is kosher in the world
        if (!evalDirs.isEmpty()) {
            double numer = 0;
            double denom = 0;
            StringBuilder comment = new StringBuilder();
            comment.append(header).append("\n");

            /**
             * If there are sub folders, we will add comments to delineate by
             * folder what the hits where. If this is just a list of files, we
             * will change naming style of the comment.
             */
            boolean added_based_on_folders = false;
            List<File> looseFiles = new ArrayList<>();
            for (File dir : evalDirs) {
                if (dir.isFile()) {
                    looseFiles.add(dir);
                    continue;
                }

                try {
                    List<Path> toTest = Files.walk(dir.toPath(), FileVisitOption.FOLLOW_LINKS)
                            .filter(Files::isRegularFile).collect(Collectors.toList());
                    for (Path p : toTest)
                        looseFiles.add(p.toFile());
                    if (!toTest.isEmpty())
                        continue;
                    comment.append(dir.getAbsoluteFile() + ":");
                    List<Path> fps = toTest.parallelStream().filter(p ->
                    {
                        try (BufferedInputStream bis = new BufferedInputStream(GZIPHelper.getStream(Files.newInputStream(p)))) {
                            return yara.match(bis);
                        } catch (IOException ex) {
                            return false;
                        }
                    }).collect(Collectors.toList());

                    denom += toTest.size();
                    numer += fps.size();
                    comment.append(fps.size() + "/" + toTest.size() + "\n");
                    added_based_on_folders = true;
                    if (!fps.isEmpty()) {
                        //TODO, write out the files that we FPd on
                    }

                } catch (IOException ex) {
                    Logger.getLogger(AutoYaraCluster.class.getName()).log(Level.SEVERE, null, ex);
                }

                yara.addComment(comment.toString());
            }

            //The loose files now get done in one go
            List<File> fps = looseFiles.parallelStream().filter(p ->
            {
                try (BufferedInputStream inputStream = new BufferedInputStream(GZIPHelper.getStream(Files.newInputStream(p.toPath())))) {
                    return yara.match(inputStream);
                } catch (IOException ex) {
                    return false;
                }
            }).collect(Collectors.toList());

            denom += looseFiles.size();
            numer += fps.size();
            if (added_based_on_folders)
                comment.append("Other Files:");
            //else, its not "other", but all
            comment.append(fps.size() + "/" + looseFiles.size() + "\n");

            //if (!fps.isEmpty()) {
                //TODO, write out the files that we FPd on
            //}
            yara.addComment(comment.toString());

            yara.outputDictionary.put(dictHeader, fps.size());
            yara.outputDictionary.put(dictHeader + "_total", looseFiles.size());

            return numer / denom;
        } else
            return 1.0;
    }

    // please call findBestRulePipelineInit, then findBestRule
    private Collection<YaraRuleContainerConjunctive> findBestRule(SortedSet<Integer> bloomSizes,
                                                      Map<Integer, CountingBloom> ben_blooms,
                                                      Map<Integer, CountingBloom> mal_blooms,
                                                      List<Path> targets) {


        this.best_rule = new ArrayList<>();
        this.best_rule_coverage = new AtomicDouble(0);
        /**
         * Whether or not we meet the goal of having at least 5 terms/features
         * in conjunctions
         */
        this.meets_min_desired_coverage = new AtomicBoolean(false);
        this.best_rule_gram_size = new AtomicInteger(1024);

        bloomSizes.stream().forEach(gram_size ->
        {

            if (best_rule_coverage.get() >= 1.0 && meets_min_desired_coverage.get())
                return;//STOP, you can't get any better

            if (!finalCandidatesCache.containsKey(gram_size)) {
                List<SigCandidate> finalCandidates = buildCandidateSet(targets, gram_size, ben_blooms, mal_blooms,
                        max_filter_size, toKeep, silent, Math.max(false_pos_b, false_pos_m));

                System.out.println("Extracted " + finalCandidates.size() + " candidates for n-gram " + gram_size);

                finalCandidatesCache.put(gram_size, finalCandidates);
            }
            List<SigCandidate> finalCandidates = finalCandidatesCache.get(gram_size);

            Set<Integer> alreadyFailedOn = new HashSet<>();

            Set<Integer> rows_covered = new HashSet<>();

            YaraRuleContainerConjunctive yara = buildRule2(finalCandidates, targets, rows_covered,
                    gram_size, alreadyFailedOn);

            if (yara == null) {
                System.out.println("failed to build rules for n-gram " + gram_size);
                return;
            }

            yara.outputDictionary.put("gram_size", gram_size);

            // currently not implemented
            double fp_rate = fpEvalDirs.isEmpty() ? 0 : addMatchEval("False Positives:", "FP_external", fpEvalDirs, yara);
            double tp_rate = tpEvalDirs.isEmpty() ? 0 : addMatchEval("True Positives:", "TP_external", tpEvalDirs, yara);

            double input_tp_rate = addMatchEval("Input TP Rate:", "TP", inDir, yara);
            // System.out.println("input tp rate " + input_tp_rate);

            if (print_rules) {
                System.out.println(yara);
                //                System.out.println("Selected " + toUse.size() + " grams to cover " + this_coverage);
            }

            if (save_all_rules) {
                try (BufferedWriter bw = new BufferedWriter(new FileWriter(new File(out_dir, name + "_" + gram_size + "_" + this.biclusterPipelineAlg + "_" + this.clusterAlg + ".yara")))) {
                    bw.write(yara.toString());
                } catch (IOException ex) {
                    Logger.getLogger(AutoYaraCluster.class.getName()).log(Level.SEVERE, null, ex);
                }
            }

            int log_diff_gram_size = log2(gram_size) - log2(best_rule_gram_size.get());

            boolean this_rule_strong = yara.minConjunctionSize() >= 5;
            double penalty = Math.min(yara.minConjunctionSize() / 5.0, 1);
            if (this.selectionHeuristic.equals("PYara")) {
                //log_diff_gram_size = 0; // old heuristic gets stuck on smaller rules constantly, we give an advantage to larger rules instead but no difference ramp!
                penalty = 1;//Math.min(yara.minConjunctionSize() / 5.0 + Math.max(0, 5 - log2(gram_size)) / 5.0, 1);; // this penalty encourages rules to be around 64/128 grams

                //penalty = 0.5 + penalty * 0.5; // penalty's power is weakened greatly to not cripple rules too much
            }
            //System.out.println(gram_size + " gram scored " + (input_tp_rate * penalty - log_diff_gram_size / 100.0) + ", TP="+input_tp_rate+", minConjunctionSize="+yara.minConjunctionSize() + ", conditions=" + yara.min_counts.size());

            if (input_tp_rate * penalty - log_diff_gram_size / 100.0 > best_rule_coverage.get() )//give a slight favor to smaller rules!
            {
                //System.out.println(gram_size + " gram replaces! gram " + best_rule_gram_size.get() + "! Scores: NEW=" + (input_tp_rate * penalty) + " vs OLD=" + (best_rule_coverage.get() + log_diff_gram_size / 100.0));

                best_rule.clear();
                best_rule.add(yara);

                best_rule_coverage.set(input_tp_rate * penalty);
                best_rule_gram_size.set(gram_size);
                meets_min_desired_coverage.set(this_rule_strong);
            }
        });

        return best_rule;
    }

    private void saveRule(Collection<YaraRuleContainerConjunctive> bestRule) throws IOException {
        this.out_file = new File(this.out_dir + "/" + this.name + ".yara");

        if (!silent)
            System.out.println("Saving rule to " + this.out_file.getAbsolutePath());

        try (BufferedWriter bw = new BufferedWriter(new FileWriter(this.out_file))) {
            YaraRuleContainerConjunctive yara = bestRule.stream().findFirst().get();
            bw.write(bestRule.toString());
        }
    }

    // please use run() only if you want it to automatically generate a YARA file at the output directory
    // otherwise, use pythonRun() to receive the YARA output as a string instead
    public void run() throws IOException {
        findBestRulePipelineInit(); // init to read files and load them as a class field

        // it is redundant to pass bloomSizes, ..., etc, but we leave it here to preserve the legacy pipeline
        Collection<YaraRuleContainerConjunctive> bestRule = findBestRule(bloomSizes, ben_blooms, mal_blooms, targets);

        if (bestRule.isEmpty()) {
            System.out.println("[GENERATION FAILED] Could not create yara-rule that matched constraints!");
            return;
        }
        saveRule(bestRule);
    }

    public HashMap<String, Object> pythonRun() throws IOException {
        // we no longer use this function from java, python will directly call it for more granular control
        //findBestRulePipelineInit(); // init to read files and load them as a class field, disabled because python has control of it

        // it is redundant to pass bloomSizes, ..., etc, but we leave it here to preserve the legacy pipeline
        Collection<YaraRuleContainerConjunctive> bestRule = findBestRule(bloomSizes, ben_blooms, mal_blooms, targets);

        if (bestRule.isEmpty()) {
            System.out.println("[GENERATION FAILED] Could not create yara-rule that matched constraints!");
            return null;
        }

        if (this.out_dir != null && !this.out_dir.trim().isEmpty())
            saveRule(bestRule);

        YaraRuleContainerConjunctive yara = bestRule.stream().findFirst().get();
        yara.appendRuleData();

        return yara.outputDictionary;
    }
}
