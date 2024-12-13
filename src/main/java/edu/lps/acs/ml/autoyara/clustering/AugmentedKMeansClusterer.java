package edu.lps.acs.ml.autoyara.clustering;

import jsat.SimpleDataSet;
import jsat.clustering.kmeans.NaiveKMeans;
import jsat.linear.distancemetrics.EuclideanDistance;

import java.util.Arrays;
public class AugmentedKMeansClusterer extends ClusteringAlgorithm {
    private final int k; // number of clusters
    private final int[] predictorLabels;

    public AugmentedKMeansClusterer(int k, int[] predictorLabels) {
        this.k = k;
        this.predictorLabels = predictorLabels;
    }

    public BiclusteringOutput cluster(SimpleDataSet sigDataset, SimpleDataSet Z) {
        BiclusteringOutput output = new BiclusteringOutput();

        // Create NaiveKMeans instance with Euclidean distance (original k-means uses Euclidean)
        NaiveKMeans kmeans = new NaiveKMeans(new EuclideanDistance());

        // Create array to store cluster assignments
        int[] joint_designations = new int[Z.size()];

        // Perform clustering with the array to store assignments
        kmeans.cluster(Z, this.k, true, joint_designations);
        System.out.println("Z dataset size: " + Z.size() + " from sigDataset size of " + sigDataset.size());
        System.out.println("augmented kmeans label designation" + Arrays.toString(predictorLabels));
        System.out.println("augmented kmeans joint designation" + Arrays.toString(joint_designations));

        createAssignments(sigDataset, Z, output, joint_designations, k);

        return output;
    }
}
