package edu.lps.acs.ml.autoyara.clustering;

import jsat.SimpleDataSet;
import jsat.clustering.kmeans.NaiveKMeans;
import jsat.linear.Matrix;
import jsat.utils.IntList;
import jsat.linear.distancemetrics.EuclideanDistance;

import java.lang.reflect.Array;
import java.util.Arrays;
import java.util.List;
import java.util.Random;

public class KMeansClusterer extends ClusteringAlgorithm {
    private final int k; // number of clusters

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

        System.out.println("kmeans joint designation" + Arrays.toString(joint_designations));

        createAssignments(sigDataset, Z, output, joint_designations, k);

        return output;
    }
}