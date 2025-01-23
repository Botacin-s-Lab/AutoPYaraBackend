package edu.lps.acs.ml.autoyara.clustering;

import jsat.SimpleDataSet;
import jsat.linear.Matrix;
import jsat.linear.DenseMatrix;
import jsat.linear.Vec;
import java.util.*;

public class AugmentedKMeansClusterer extends ClusteringAlgorithm {
    public double alpha; // Corruption level parameter

    public AugmentedKMeansClusterer(int k) {
        this.k = k;
        this.alpha = 0.1; // Can be made configurable
    }

    @Override
    public BiclusteringOutput cluster(SimpleDataSet sigDataset, SimpleDataSet Z) {
        BiclusteringOutput output = new BiclusteringOutput();
        Matrix A = Z.getDataMatrix();
        int n = A.rows();
        int d = A.cols();

        // Step 1: Create Yi sets based on predictor labels
        List<List<Integer>> Yi = new ArrayList<>(k);
        for (int i = 0; i < k; i++) {
            Yi.add(new ArrayList<>());
        }

        // Group points by predictor labels
        // Yi now contains a list of sample indices for each k
        /*
            Suppose cluster designation is [0, 1, 1, 0, 0]
            Yi = [
                [1, 4, 5], # cluster 0
                [2, 3], # cluster 1
            ]
         */
        for (int i = 0; i < n; i++) {
            Yi.get(this.predictorLabels[i]).add(i);
        }

        // Step 2-4: Run CRDEST for each coordinate of each Yi
        double[][] centroids = new double[k][d];

        for (int i = 0; i < k; i++) {
            List<Integer> points = Yi.get(i);
            if (points.isEmpty()) continue;

            // For each coordinate/feature
            for (int j = 0; j < d; j++) {
                // Extract the j-th coordinate values for points in Yi
                double[] coords = new double[points.size() * 2];
                int idx = 0;
                for (int pointIdx : points) {
                    coords[idx++] = A.get(pointIdx, j);
                }

                // Run CRDEST
                double coordEstimate = runCRDEST(coords, this.alpha);
                centroids[i][j] = coordEstimate;
            }
        }

        // Convert centroids to cluster assignments
        int[] joint_designations = assignToClusters(A, centroids);
        System.out.println("augmented kmeans joint designation" + Arrays.toString(joint_designations));

        // Create final output
        createAssignments(sigDataset, Z, output, joint_designations, k);
        return output;
    }

    private double runCRDEST(double[] points, double alpha) {
        int m = points.length / 2;

        // Step 1: Randomly partition points into X1 and X2
        Random rand = new Random();
        List<Double> allPoints = new ArrayList<>();
        for (double point : points) {
            allPoints.add(point);
        }
        Collections.shuffle(allPoints, rand);

        List<Double> X1 = allPoints.subList(0, m);
        List<Double> X2 = allPoints.subList(m, points.length);

        // Step 2: Find shortest interval I containing m(1-5α) points of X1
        Collections.sort(X1);
        int windowSize = (int)(m * (1 - 5 * alpha));
        double minInterval = Double.MAX_VALUE;
        double intervalStart = X1.get(0);

        for (int i = 0; i <= X1.size() - windowSize; i++) {
            double interval = X1.get(i + windowSize - 1) - X1.get(i);
            if (interval < minInterval) {
                minInterval = interval;
                intervalStart = X1.get(i);
            }
        }

        // Step 3: Find points in X2 that fall within interval I
        List<Double> Z = new ArrayList<>();
        double intervalEnd = intervalStart + minInterval;
        for (double x : X2) {
            if (x >= intervalStart && x <= intervalEnd) {
                Z.add(x);
            }
        }

        // Step 4: Return average of points in Z
        if (Z.isEmpty()) {
            // Fallback: return median of all points if Z is empty
            Collections.sort(allPoints);
            return allPoints.get(allPoints.size() / 2);
        }

        double sum = 0;
        for (double z : Z) {
            sum += z;
        }
        return sum / Z.size();
    }

    private int[] assignToClusters(Matrix A, double[][] centroids) {
        int[] assignments = new int[A.rows()];

        for (int i = 0; i < A.rows(); i++) {
            double minDist = Double.MAX_VALUE;
            int bestCluster = 0;

            for (int j = 0; j < centroids.length; j++) {
                double dist = 0;
                for (int d = 0; d < A.cols(); d++) {
                    double diff = A.get(i, d) - centroids[j][d];
                    dist += diff * diff;
                }

                if (dist < minDist) {
                    minDist = dist;
                    bestCluster = j;
                }
            }

            assignments[i] = bestCluster;
        }

        return assignments;
    }
}