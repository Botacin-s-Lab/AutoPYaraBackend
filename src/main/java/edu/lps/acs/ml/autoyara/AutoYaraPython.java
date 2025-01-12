package edu.lps.acs.ml.autoyara;

import com.beust.jcommander.Parameter;
import edu.lps.acs.ml.autoyara.clustering.*;
import jsat.SimpleDataSet;
import jsat.classifiers.DataPoint;
import jsat.clustering.biclustering.SpectralCoClustering;
import jsat.linear.*;
import jsat.math.OnLineStatistics;
import jsat.utils.IntList;
import jsat.utils.concurrent.AtomicDouble;

import java.io.BufferedWriter;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
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
    public File out_dir;

    // These parameters are optional, but are necessary for some clustering algorithms
    public int[] predictorLabels; // required by augmented kmeans
    public int k = 0; // required by kmeans, random, and augmented kmeans, 0 or less will automatically set it to # samples * 0.3

    // We define these parameters here to make it simple to resume (some processes need to be injected w/ python code)
    SortedSet<Integer> bloomSizes;
    Map<Integer, CountingBloom> ben_blooms;
    Map<Integer, CountingBloom> mal_blooms;
    List<Path> targets;

    Collection<YaraRuleContainerConjunctive> best_rule = new ArrayList<>();
    AtomicDouble best_rule_coverage = new AtomicDouble(0);
    AtomicBoolean meets_min_desired_coverage = new AtomicBoolean(false);
    AtomicInteger best_rule_gram_size = new AtomicInteger(0);

    public AutoYaraPython() {
        // we copy AutoYaraCluster + all of its parameters
        // in future iterations we will slowly migrate dependency only to this file
        super();
        myBloom = new Bytes2Bloom();
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
            System.out.println("Clusterer: using VBGMM");
            clusterer = new VBGMMClusterer();
        } else if (this.clusterAlg.equals("KMeans")) {
            System.out.println("Clusterer: using KMeans with k " + selectedK);
            clusterer = new KMeansClusterer(selectedK);

            if (this.generateName)
                this.name += "_k" + selectedK;
        } else if (this.clusterAlg.equals("Random")) {
            System.out.println("Clusterer: using Random with k " + selectedK);
            clusterer = new RandomClusterer(selectedK);

            if (this.generateName)
                this.name += "_k" + selectedK;
        } else if (this.clusterAlg.equals("AugmentedKMeans")) {
            System.out.println("Clusterer: using AugmentedKMeans with k " + selectedK);
            clusterer = new AugmentedKMeansClusterer(selectedK, this.predictorLabels);

            if (this.generateName)
                this.name += "_k" + selectedK;
        } else {
            System.out.println("Cluster algorithm " + this.clusterAlg + " not found. Defaulting to VBGMM clusterer.");
            System.out.println("Clusterer: using VBGMM");
            clusterer = new VBGMMClusterer();
        }

        if (this.biclusterPipelineAlg.equals("SpectralCoCluster")) {
            SpectralCoClusterPipeline bc = new SpectralCoClusterPipeline(selectedK);
            bc.inputNormalization = SpectralCoClustering.InputNormalization.BISTOCHASTIZATION;
            System.out.println("Biclustering: using SpectralCoCluster with bistochastic normalization");
            out = bc.bicluster(sigDataset, clusterer);
        } else if (this.biclusterPipelineAlg.equals("SpectralCoClusterScale")) {
            SpectralCoClusterPipeline bc = new SpectralCoClusterPipeline(selectedK);
            bc.inputNormalization = SpectralCoClustering.InputNormalization.SCALE;
            System.out.println("Biclustering: using SpectralCoCluster with scale normalization");
            out = bc.bicluster(sigDataset, clusterer);
        } else {
            System.out.println("Bicluster algorithm " + this.biclusterPipelineAlg + " not found. Defaulting to SpectralCoClustering with Scale normalization.");

            SpectralCoClusterPipeline bc = new SpectralCoClusterPipeline(selectedK);
            bc.inputNormalization = SpectralCoClustering.InputNormalization.SCALE;
            out = bc.bicluster(sigDataset, clusterer);
        }
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

        YaraRuleContainerConjunctive yara = new YaraRuleContainerConjunctive(N, this.name); // initialize a new yara container

        if(D == 0)//No candidates, nothing to do :(
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
        if(D == 1) //if we only have 1 candidate, we don't need to bicluster
        {
            col_clusters.add(IntList.range(D));
            row_clusters.add(IntList.range(N));
        }
        else
        {
            BiclusteringOutput out = runCoclusterAlg(sigDataset);
            col_clusters.addAll(out.columnAssignments);
            row_clusters.addAll(out.rowAssignments);

            if(!alreadyFailedOn.contains(gram_size) && (row_clusters.isEmpty() || col_clusters.isEmpty()))
            {
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
        }

        // stage 4: acquire max_row_size_seen, max_features_seen, min_rows, min_features, feature_counts_all
        int max_row_size_seen = row_clusters.stream().mapToInt(r->r.size()).max().orElse(1); // what was the most files a feature covered?
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
        int max_features_seen = IntStream.range(0, row_clusters.size()).map(c-> // how many features had 50% coverage or more?
        {
            int C_size = row_clusters.get(c).size();
            int[] feature_counts = feature_counts_all.get(c);
            return (int)col_clusters.get(c).stream().filter(j->feature_counts[j] >= 0.5*C_size).count();
        }).max().orElse(1);

        if(max_features_seen < min_features) // if we didn't mean the min, subtract an extra b/c otherwise we need the min count to hit the max rows, which is not likely
            min_features = Math.max(max_features_seen-1, 1);

        // stage 5: for each good cluster, perform statistics to build the smallest conjunction set that also has good coverage
        for (int c = 0; c < row_clusters.size(); c++)
        {
            int C_size = row_clusters.get(c).size();
            if(C_size < min_rows) // pick only clusters that cover a lot of files
                continue;
            int[] feature_counts = feature_counts_all.get(c);

            //First, lets remove obvious non-starters. You need to appear in at least half the files in your cluster
            Set<Integer> selected_features = new HashSet<>(col_clusters.get(c));

            //We are only going to consider features that occur in >= 50% of this cluster
            selected_features.removeIf(j-> feature_counts[j] < 0.5*C_size);

            if(selected_features.size() < min_features)
                continue;

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

            yara.addSignature(count_min, selected_features.stream().map(i->finalCandidates.get(i)).collect(Collectors.toSet()));

        }
        return yara;
    }

    private void initializeOutputFile() {
        if (out_file == null)
            out_file = new File(inDir.get(0).getName() + ".yara");

        this.name = out_file.getName().replace(".yara", "");

        if (out_file.isDirectory()) {
            this.out_dir = out_file;
            out_file = new File(out_dir, name);
        } else
            this.out_dir = out_file.getParentFile();
    }

    private SortedSet<Integer> collectBloomSizes() throws IOException {
        SortedSet<Integer> bloomSizes = new ConcurrentSkipListSet<>((a, b) -> b.compareTo(a));
        collectBloomSizes(bloomSizes, benign_bloom_dir, malicious_bloom_dir);
        return bloomSizes;
    }

    private void findBestRulePipelineInit() throws IOException {
        initializeOutputFile();

        this.bloomSizes = collectBloomSizes();
        this.ben_blooms = collectBloomFilters(benign_bloom_dir);
        this.mal_blooms = collectBloomFilters(malicious_bloom_dir);
        this.targets = AutoYaraPython.getAllChildrenFiles(inDir);

        // no name specified? generate a name for the YARA rule
        if (this.name == null || this.name.trim().isEmpty()) {
            this.generateName = true; // if this is true, the entire pipeline will append information to the rule name
            this.name = "generated_rule";
        } else {
            this.generateName = false;
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

    private List<SigCandidate>  findBestRulePipelineCandidateSet(Integer gram_size) {
        if (best_rule_coverage.get() >= 1.0 && meets_min_desired_coverage.get())
            return new ArrayList<>(); //STOP, you can't get any better

        List<SigCandidate> finalCandidates = buildCandidateSet(targets, gram_size, ben_blooms, mal_blooms,
                max_filter_size, toKeep, silent, Math.max(false_pos_b, false_pos_m));

        return finalCandidates;
    }

    private void findBestRulePipelineClustering(Integer gram_size, List<SigCandidate> finalCandidates) {
        Set<Integer> alreadyFailedOn = new HashSet<>();

        Set<Integer> rows_covered = new HashSet<>();

        YaraRuleContainerConjunctive yara = buildRule2(finalCandidates, targets, rows_covered,
                gram_size, alreadyFailedOn);

        double fp_rate = fpEvalDirs.isEmpty() ? 0 : addMatchEval("False Positives:", fpEvalDirs, yara);
        double tp_rate = tpEvalDirs.isEmpty() ? 0 : addMatchEval("True Positives:", tpEvalDirs, yara);
        double input_tp_rate = addMatchEval("Input TP Rate:", inDir, yara);

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

        if (input_tp_rate * penalty > best_rule_coverage.get() + log_diff_gram_size / 100.0)//give a slight favor to smaller rules!
        {
            best_rule.clear();
            best_rule.add(yara);

            best_rule_coverage.set(input_tp_rate * penalty);
            best_rule_gram_size.set(gram_size);
            meets_min_desired_coverage.set(this_rule_strong);
        }
    }

    // deprecated, please findBestRulePipelineInit, then findBestRulePipelineCandidateSet + findBestRulePipelineClustering
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
        this.best_rule_gram_size = new AtomicInteger(0);

        bloomSizes.stream().forEach(gram_size ->
        {

            if (best_rule_coverage.get() >= 1.0 && meets_min_desired_coverage.get())
                return;//STOP, you can't get any better

            List<SigCandidate> finalCandidates = buildCandidateSet(targets, gram_size, ben_blooms, mal_blooms,
                    max_filter_size, toKeep, silent, Math.max(false_pos_b, false_pos_m));

            Set<Integer> alreadyFailedOn = new HashSet<>();

            Set<Integer> rows_covered = new HashSet<>();

            YaraRuleContainerConjunctive yara = buildRule2(finalCandidates, targets, rows_covered,
                    gram_size, alreadyFailedOn);

            double fp_rate = fpEvalDirs.isEmpty() ? 0 : addMatchEval("False Positives:", fpEvalDirs, yara);
            double tp_rate = tpEvalDirs.isEmpty() ? 0 : addMatchEval("True Positives:", tpEvalDirs, yara);
            double input_tp_rate = addMatchEval("Input TP Rate:", inDir, yara);

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

            if (input_tp_rate * penalty > best_rule_coverage.get() + log_diff_gram_size / 100.0)//give a slight favor to smaller rules!
            {
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
        if (!silent)
            System.out.println("Saving rule to " + out_file.getAbsolutePath());
        try (BufferedWriter bw = new BufferedWriter(new FileWriter(out_file))) {
            YaraRuleContainerConjunctive yara = bestRule.stream().findFirst().get();
            bw.write(bestRule.toString());
        }
    }

    private String getRuleString(Collection<YaraRuleContainerConjunctive> bestRule) {
        YaraRuleContainerConjunctive yara = bestRule.stream().findFirst().get();
        return yara.toString();
    }

    // please use run() only if you want it to automatically generate a YARA file at the output directory
    // otherwise, use pythonRun() to receive the YARA output as a string instead
    public void run() throws IOException {
        findBestRulePipelineInit(); // init to read files and load them as a class field

        // it is redundant to pass bloomSizes, ..., etc, but we leave it here to preserve the legacy pipeline
        Collection<YaraRuleContainerConjunctive> bestRule = findBestRule(bloomSizes, ben_blooms, mal_blooms, targets);

        if (bestRule.isEmpty()) {
            System.out.println("Could not create yara-rule that matched constraints :(");
            return;
        }

        saveRule(bestRule);
    }

    public String pythonRun() throws IOException {
        findBestRulePipelineInit(); // init to read files and load them as a class field

        // it is redundant to pass bloomSizes, ..., etc, but we leave it here to preserve the legacy pipeline
        Collection<YaraRuleContainerConjunctive> bestRule = findBestRule(bloomSizes, ben_blooms, mal_blooms, targets);

        if (bestRule.isEmpty()) {
            System.out.println("Could not create yara-rule that matched constraints :(");
            return "";
        }

        this.name = ""; // after a rule generation, name must be wiped so it can be generated again for the next session

        return getRuleString(bestRule);
        // saveRule(bestRule);
    }
}
