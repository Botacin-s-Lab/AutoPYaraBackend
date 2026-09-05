/*
 * Part of AutoPYaraBackend.
 * Copyright (c) 2026 Botacin's Lab. Licensed under the MIT License; see LICENSE.
 *
 * Original work -- not derived from upstream AutoYara. See NOTICE.
 */
package edu.lps.acs.ml.autoyara.clustering;

import jsat.SimpleDataSet;
import jsat.clustering.kmeans.NaiveKMeans;
import jsat.linear.Matrix;
import jsat.linear.Vec;
import jsat.utils.IntList;
import jsat.linear.distancemetrics.EuclideanDistance;

import java.lang.reflect.Array;
import java.util.Arrays;
import java.util.List;
import java.util.Random;

public class KMeansClusterer extends ClusteringAlgorithm {
    public KMeansClusterer(int k) {
        this.k = k;
    }

    public BiclusteringOutput cluster(SimpleDataSet sigDataset, SimpleDataSet Z) {
        BiclusteringOutput output = new BiclusteringOutput();

        // Create NaiveKMeans instance with Euclidean distance (original k-means uses Euclidean)
        NaiveKMeans kmeans = new NaiveKMeans(new EuclideanDistance());

        // Create array to store cluster assignments
        int[] joint_designations = new int[Z.size()];

        // Perform clustering with the array to store assignments
        kmeans.cluster(Z, this.k, true, joint_designations);

        //System.out.println("kmeans "+ this.k + " joint designation" + Arrays.toString(joint_designations));

        createAssignments(sigDataset, Z, output, joint_designations, k);
        output.k_used = this.k;

        return output;
    }
}