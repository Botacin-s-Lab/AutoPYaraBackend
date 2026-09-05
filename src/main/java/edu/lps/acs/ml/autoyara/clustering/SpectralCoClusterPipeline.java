/*
 * Part of AutoPYaraBackend.
 * Copyright (c) 2026 Botacin's Lab. Licensed under the MIT License; see LICENSE.
 *
 * Original work -- not derived from upstream AutoYara. See NOTICE.
 */
package edu.lps.acs.ml.autoyara.clustering;

import edu.lps.acs.ml.autoyara.clustering.BiclusteringOutput;
import jsat.SimpleDataSet;
import jsat.classifiers.CategoricalData;
import jsat.classifiers.DataPoint;
import jsat.clustering.biclustering.SpectralCoClustering;
import jsat.linear.DenseVector;
import jsat.linear.Matrix;
import jsat.linear.SubMatrix;
import jsat.linear.TruncatedSVD;

import java.util.Arrays;
import java.util.List;

public class SpectralCoClusterPipeline implements BiclusteringPipeline {
    // TODO: properly port the members to be private
    public static SpectralCoClustering.InputNormalization DEFAULT = SpectralCoClustering.InputNormalization.BISTOCHASTIZATION;
    public SpectralCoClustering.InputNormalization inputNormalization = SpectralCoClustering.InputNormalization.BISTOCHASTIZATION;

    public int k = 0;
    public SpectralCoClusterPipeline(int k) {
        this.k = k;
    }
    public String predictorExtensionMode = "NearestCluster";

    public BiclusteringOutput bicluster(SimpleDataSet sigDataset, ClusteringAlgorithm clusterer, int[] predictorLabels) {
        //﻿1. Given A, form An = D_1^{−1/2} A D_2^{−1/2}
        Matrix A = sigDataset.getDataMatrix();

        DenseVector R = new DenseVector(A.rows());
        DenseVector C = new DenseVector(A.cols());

        /* System.out.println("biclustering algorithm: sigDataset has # rows " + A.rows() + " and # columns " + A.cols());
        for (int j = 0; j < A.cols(); j++) {
            int score = 0;
            for (int i = 0; i < A.rows(); i++) {
                if (A.get(i, j) > 0)
                    score++;
            }

            System.out.println("Feature " + j + " covers " + score + " samples");
        }*/

        Matrix A_n = inputNormalization.normalize(A, R, C);

        //﻿2. Compute l = ceil(log2 k) singular vectors of A_n, u2, . . . u_l+1 and v2, . . . v_l+1, and form the matrix Z as in (12)
        // k was previously estimated using the k_max heuristic below, however, this estimation is now done upstream in the pipeline
        // int k_max = Math.min(A.rows(), A.cols());
        // int l = Math.min(A.rows(), A.cols());
        int l = (int) Math.ceil(Math.log(k)/Math.log(2.0));

        if (l <= 0) {
            // just in case upstream k fails, we make l nonzero
            // System.out.println("l is <= 0!, setting l = 1, k = " + this.k);
            l = 1;
        }
        if (predictorLabels != null && clusterer.requirePredictorLabel) {
            // problem: predictorLabels are assigned to the original rows of the matrix only, how do we extend to the columns during Z transforamtion?
            // for clustering algorithms that need a predictor label transformed to Z, we allow several options
            // NewLabel: add a new cluster and assign it to all V components <- using this right now
            // Separate: each new feature has a separate label, unimplemented
            // NearestCluster: assign the feature to the same cluster as the samples its most commonly found in, unimplemented

            int[] transformedPredictorLabels = new int[A.rows() + A.cols()];

            if (this.predictorExtensionMode.equals("NewLabel")) {
                this.k = k + 1;
                l = (int) Math.ceil(Math.log(this.k)/Math.log(2.0));

                if (A.rows() >= 0) System.arraycopy(predictorLabels, 0, transformedPredictorLabels, 0, A.rows());
                for (int i = 0; i < A.cols(); i++)
                    transformedPredictorLabels[i + predictorLabels.length] = this.k-1; // we use k-1 instead of k since clusters start at 0
            } else if (this.predictorExtensionMode.equals("NearestCluster")) {
                // Copy existing predictor labels for the rows
                if (A.rows() >= 0) System.arraycopy(predictorLabels, 0, transformedPredictorLabels, 0, A.rows());

                // For each column/feature
                for (int col = 0; col < A.cols(); col++) {
                    // Keep count of connections to each cluster
                    int[] clusterCounts = new int[k];
                    double[] clusterSums = new double[k];

                    // Look at all rows for this column
                    for (int row = 0; row < A.rows(); row++) {
                        double value = A.get(row, col);
                        if (value > 0) {  // Consider only non-zero connections
                            int cluster = predictorLabels[row];
                            clusterCounts[cluster]++;
                            clusterSums[cluster] += value;
                        }
                    }

                    // Find cluster with strongest connection
                    int bestCluster = 0;
                    double bestScore = 0;
                    for (int cluster = 0; cluster < k; cluster++) {
                        // Use average value as score to avoid bias towards larger clusters
                        double score = clusterCounts[cluster] > 0 ?
                                clusterSums[cluster] / clusterCounts[cluster] : 0;
                        if (score > bestScore) {
                            bestScore = score;
                            bestCluster = cluster;
                        }
                    }

                    // Assign feature to its nearest cluster
                    transformedPredictorLabels[A.rows() + col] = bestCluster;
                }

                clusterer.setPredictorLabels(transformedPredictorLabels);
            }

            clusterer.setPredictorLabels(transformedPredictorLabels);
            clusterer.setK(this.k);
            //System.out.println("generated predictor labels: " + Arrays.toString(transformedPredictorLabels));
        }

        //A_n has r rows and c columns. We are going to make a new data matrix Z
        //Z will have (r+c) rows, and l columns.
        SimpleDataSet Z = create_Z_dataset(A_n, l, R, C, inputNormalization);//+1 b/c we are going to skip the first SV
        if (Z == null)
            return null;

//        System.out.println("SimpleDataSet2");
//        Matrix Zm = Z.getDataMatrix();
//        for (int i = 0; i < Zm.rows(); i++) {
//            for (int j = 0; j < Zm.cols(); j++) {
//                double value = Zm.get(i, j);
//                System.out.print(value + ", ");
//            }
//            System.out.print("\n");
//        }

        // cluster Z

        return clusterer.cluster(sigDataset, Z);
    }

    private SimpleDataSet create_Z_dataset(Matrix A_n, int l, DenseVector R, DenseVector C, SpectralCoClustering.InputNormalization inputNormalization)
    {
        //A_n has r rows and c columns. We are going to make a new data matrix Z
        //Z will have (r+c) rows, and l columns.
        TruncatedSVD svd = new TruncatedSVD(A_n, l+1);//+1 b/c we are going to skip the first SV
        Matrix U = svd.getU();
        Matrix V = svd.getV().transpose();
        //In some cases, Drop the first column, which corresponds to the first SV we don't want
        int to_skip = 1;

        try {
            U = new SubMatrix(U, 0, to_skip, U.rows(), l+to_skip);
            V = new SubMatrix(V, 0, to_skip, V.rows(), l+to_skip);
        } catch(ArithmeticException e) {
            // System.out.println("cannot use VBGMM, dataset too small!");
            return null;
        }

        /* Orig paper says to do this multiplication for re-scaling. Why not for
         * bistochastic? Its very similar! b/c in "﻿Spectral Biclustering of
         * Microarray Data: Coclustering Genes and Conditions" where bistochastic
         * is introduced, on page 710: "﻿Once D1 and D2 are found, we ﻿apply SVD to
         * B with no further normalization "
         *
         */
        if(inputNormalization == SpectralCoClustering.InputNormalization.SCALE)
        {
            Matrix.diagMult(R, U);
            Matrix.diagMult(C, V);
        }

        SimpleDataSet Z = new SimpleDataSet(l, new CategoricalData[0]);
        for(int i = 0; i < U.rows(); i++)
            Z.add(new DataPoint(U.getRow(i)));
        for(int i = 0; i < V.rows(); i++)
            Z.add(new DataPoint(V.getRow(i)));
        return Z;
    }
}
