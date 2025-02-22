package edu.lps.acs.ml.autoyara.clustering;

import jsat.SimpleDataSet;
import jsat.linear.Matrix;

public class AugmentedKMeansSoftClusterer extends AugmentedKMeansClusterer {
    public double m = 2; // fuzzy parameter

    public AugmentedKMeansSoftClusterer(int k) {
        super(k);
    }

    @Override
    public BiclusteringOutput cluster(SimpleDataSet sigDataset, SimpleDataSet Z) {
        BiclusteringOutput output = new BiclusteringOutput();
        Matrix A = Z.getDataMatrix();

        double[][] bestCentroids = computeCentroids(A);
        double[][] mixtureAssignment = buildMixtureAssignment(bestCentroids, sigDataset, Z, output, this.k, this.m);

        // Create final output
        createMixtureAssignments(sigDataset, Z, output, mixtureAssignment, this.k);
        output.k_used = k;

        return output;
    }
}
