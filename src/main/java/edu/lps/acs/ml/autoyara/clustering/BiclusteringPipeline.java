/*
 * Part of AutoPYaraBackend.
 * Copyright (c) 2026 Botacin's Lab. Licensed under the MIT License; see LICENSE.
 *
 * Original work -- not derived from upstream AutoYara. See NOTICE.
 */
package edu.lps.acs.ml.autoyara.clustering;

import edu.lps.acs.ml.autoyara.clustering.BiclusteringOutput;
import jsat.SimpleDataSet;

import java.util.List;

public interface BiclusteringPipeline {
    public BiclusteringOutput bicluster(SimpleDataSet sigDataset, ClusteringAlgorithm clusterer, int[] predictorLabels);
}
