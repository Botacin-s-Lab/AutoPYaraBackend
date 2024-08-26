package edu.lps.acs.ml.autoyara;

import com.beust.jcommander.Parameter;
import com.google.common.primitives.Bytes;
import edu.lps.acs.ml.ngram3.utils.FileConverter;
import jsat.clustering.biclustering.SpectralCoClustering;

import java.io.File;
import java.io.IOException;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 *  DOCUMENTATION
 *
 *  ABOUT
 *      This class serves to run AutoYara given a python interface. In the future, you should NOT
 *      access any other classes when using jpype. This is to prevent uncessary coupling and to
 *      facilitate future development for CapyMOA/MOA integration.
 *
 *  PIPELINE (still WIP, behavior isn't implemented)
 *      "Training"
 *          - call buildBloomFiles
 *          - specify directories and other configuration parameters
 *          - bloom filters are now generated
 *          - done
 *
 *      Yara Generation (planning, subject to change)
 *          - provide directories and parameters
 *          - generate candidates via buildCandidateSet
 *          - set of candidates is now passed back to python
 *          - in python class, read user specification for which bicluster and cluster to use
 *          - in python class, pass candidates to selected biclustering and clustering algorithms
 *          - output is a YaraRuleContainerConjunctive object
 *          - take output and pass it through the rest of the filtering code
 *          - code should then generate an output file
 */

public class AutoYaraPython extends AutoYaraCluster {
    private Bytes2Bloom myBloom;



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
    public List<SigCandidate> buildCandidateSet(File in_dir, int gram_size, File ben_blooms_dir, File mal_blooms_dir)
            throws IOException
    {
        List<Path> targets = AutoYaraCluster.getAllChildrenFiles(in_dir);
        Map<Integer, CountingBloom> ben_blooms = AutoYaraCluster.collectBloomFilters(ben_blooms_dir);
        Map<Integer, CountingBloom> mal_blooms = AutoYaraCluster.collectBloomFilters(mal_blooms_dir);

        return AutoYaraCluster.buildCandidateSet(targets, gram_size, ben_blooms, mal_blooms, this.max_filter_size, toKeep, silent, Math.max(false_pos_b, false_pos_m));
    }

    static public YaraRuleContainerConjunctive buildRule(List<SigCandidate> finalCandidates, List<Path> targets, Set<Integer> rows_covered, final String name, SpectralCoClustering.InputNormalization normalization, int gram_size, Set<Integer> alreadyFailedOn) {
        return AutoYaraCluster.buildRule(finalCandidates, targets, rows_covered, name, normalization, gram_size, alreadyFailedOn);
    }
}
