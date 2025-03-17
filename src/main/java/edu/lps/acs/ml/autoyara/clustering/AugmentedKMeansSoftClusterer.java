package edu.lps.acs.ml.autoyara.clustering;

import jsat.SimpleDataSet;
import jsat.linear.Matrix;

import java.util.Arrays;

public class AugmentedKMeansSoftClusterer extends AugmentedKMeansClusterer {
    public double m = 3; // fuzzy parameter

    public AugmentedKMeansSoftClusterer(int k) {
        super(k);
    }

    @Override
    public BiclusteringOutput cluster(SimpleDataSet sigDataset, SimpleDataSet Z) {
        BiclusteringOutput output = new BiclusteringOutput();
        Matrix A = Z.getDataMatrix();

        double[][] bestCentroids = computeCentroids(A);
        double[][] mixtureAssignment = buildMixtureAssignment(bestCentroids, sigDataset, Z, output, this.k, this.m);

        // this code block is used to test clustering behaviors for AKMS and VBGMM to make graphs
//        System.out.println("Predictor Labels" + Arrays.toString(this.predictorLabels));
//        AugmentedKMeansClusterer AKMS = new AugmentedKMeansClusterer(this.k);
//        AKMS.predictorLabels = this.predictorLabels;
//        AKMS.cluster(sigDataset, Z);
//
//        for (int i = 0; i < k; i++) {
//            // For each coordinate/feature
//            for (int j = 0; j < A.cols(); j++) {
//                System.out.print(bestCentroids[i][j] + ", ");
//            }
//            System.out.print("\n");
//        }
//
//        VBGMMClusterer VBGMM = new VBGMMClusterer();
//        VBGMM.cluster(sigDataset, Z);

        // Create final output
        createMixtureAssignments(sigDataset, Z, output, mixtureAssignment, this.k);
        output.k_used = this.k;

        return output;
    }
}
