/*
 * Part of AutoPYaraBackend.
 * Copyright (c) 2026 Botacin's Lab. Licensed under the MIT License; see LICENSE.
 *
 * Original work -- not derived from upstream AutoYara. See NOTICE.
 */
package edu.lps.acs.ml.autoyara.clustering;

import jsat.SimpleDataSet;
import jsat.clustering.kmeans.NaiveKMeans;
import jsat.linear.distancemetrics.EuclideanDistance;

import java.util.Arrays;
import java.util.Random;

/*
    This clustering algorithm simply picks a random cluster for every point.
    It is intended to test baselines and should not be used for real world applications.
 */
public class RandomClusterer extends ClusteringAlgorithm {
    private final int k; // number of clusters

    public RandomClusterer(int k) {
        this.k = k;
    }

    public BiclusteringOutput cluster(SimpleDataSet sigDataset, SimpleDataSet Z) {
        BiclusteringOutput output = new BiclusteringOutput();

        // Create NaiveKMeans instance with Euclidean distance (original k-means uses Euclidean)
        NaiveKMeans kmeans = new NaiveKMeans(new EuclideanDistance());

        // Create array to store cluster assignments
        int[] joint_designations = new int[Z.size()];

        // Perform clustering with the array to store assignments
        // kmeans.cluster(Z, this.k, true, joint_designations);

        Random r = new Random();
        for (int i = 0; i < Z.size(); i++) {
            joint_designations[i] = r.nextInt(k);
        }

        System.out.println("random joint designation" + Arrays.toString(joint_designations));

        createAssignments(sigDataset, Z, output, joint_designations, k);
        output.k_used = k;

        return output;
    }
}
