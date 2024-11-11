package edu.lps.acs.ml.autoyara.clustering;

import edu.lps.acs.ml.autoyara.clustering.BiclusteringOutput;
import jsat.SimpleDataSet;
import jsat.linear.Matrix;

import java.util.List;

public interface ClusteringAlgorithm {
    public BiclusteringOutput cluster(SimpleDataSet sigDataset, SimpleDataSet Z);
}
