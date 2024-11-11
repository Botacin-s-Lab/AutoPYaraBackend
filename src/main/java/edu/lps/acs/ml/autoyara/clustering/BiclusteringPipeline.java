package edu.lps.acs.ml.autoyara.clustering;

import edu.lps.acs.ml.autoyara.clustering.BiclusteringOutput;
import jsat.SimpleDataSet;

import java.util.List;

public interface BiclusteringPipeline {
    public BiclusteringOutput bicluster(SimpleDataSet sigDataset, ClusteringAlgorithm clusterer);
}
