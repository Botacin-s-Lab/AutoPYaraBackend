package edu.lps.acs.ml.autoyara.clustering;

import jsat.SimpleDataSet;
import jsat.clustering.kmeans.NaiveKMeans;
import jsat.linear.distancemetrics.EuclideanDistance;

import java.util.Arrays;
public class AugmentedKMeansClusterer extends ClusteringAlgorithm {
    public AugmentedKMeansClusterer(int k) {
        this.k = k;
    }

    public BiclusteringOutput cluster(SimpleDataSet sigDataset, SimpleDataSet Z) {
        BiclusteringOutput output = new BiclusteringOutput();
        // TODO: perform the actual AugmentedClustering, use Z and this.predictorLabels to create joint designations

        // Create NaiveKMeans instance with Euclidean distance (original k-means uses Euclidean)
        NaiveKMeans kmeans = new NaiveKMeans(new EuclideanDistance());

        // Create array to store cluster assignments
        int[] joint_designations = new int[Z.size()];

        // Perform clustering with the array to store assignments
        kmeans.cluster(Z, this.k, true, joint_designations);
        System.out.println("Z dataset size: " + Z.size() + " from sigDataset size of " + sigDataset.size());
        System.out.println("augmented kmeans label designation" + Arrays.toString(this.predictorLabels));
        System.out.println("augmented kmeans joint designation" + Arrays.toString(joint_designations));

        createAssignments(sigDataset, Z, output, joint_designations, k);

        return output;
    }
}
