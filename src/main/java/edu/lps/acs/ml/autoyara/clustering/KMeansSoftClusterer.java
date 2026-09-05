/*
 * Part of AutoPYaraBackend.
 * Copyright (c) 2026 Botacin's Lab. Licensed under the MIT License; see LICENSE.
 *
 * Original work -- not derived from upstream AutoYara. See NOTICE.
 */
package edu.lps.acs.ml.autoyara.clustering;

import jsat.SimpleDataSet;
import jsat.clustering.kmeans.NaiveKMeans;
import jsat.linear.Vec;
import jsat.linear.distancemetrics.EuclideanDistance;
import jsat.linear.Matrix;

import java.util.stream.IntStream;
import java.util.List;

public class KMeansSoftClusterer extends KMeansClusterer {
    public double m = 3; // fuzzy parameter

    public KMeansSoftClusterer(int k) {
        super(k);
    }

    public BiclusteringOutput cluster(SimpleDataSet sigDataset, SimpleDataSet Z) {
        BiclusteringOutput output = new BiclusteringOutput();

        // Create NaiveKMeans instance with Euclidean distance (original k-means uses Euclidean)
        NaiveKMeans kmeans = new NaiveKMeans(new EuclideanDistance());

        // Create array to store cluster assignments
        int[] joint_designations = new int[Z.size()];

        // Perform clustering with the array to store assignments
        kmeans.cluster(Z, this.k, true, joint_designations);

        Matrix A = Z.getDataMatrix();
        int n = A.rows();
        int d = A.cols();

        List<Vec> means = kmeans.getMeans();

        double[][] centroids = IntStream.range(0, this.k)
                .mapToObj(i -> IntStream.range(0, d)
                        .mapToDouble(j -> means.get(i).get(j))
                        .toArray())
                .toArray(double[][]::new);

        double[][] mixtureAssignment = buildMixtureAssignment(centroids, sigDataset, Z, output, this.k, this.m);

        // Create final output
        createMixtureAssignments(sigDataset, Z, output, mixtureAssignment, this.k);
        output.k_used = this.k;

        return output;
    }
}
