package edu.lps.acs.ml.autoyara.clustering;

import edu.lps.acs.ml.autoyara.SigCandidate;
import edu.lps.acs.ml.autoyara.clustering.BiclusteringOutput;
import jsat.SimpleDataSet;
import jsat.clustering.VBGMM;
import jsat.linear.Matrix;
import jsat.utils.IntList;

import java.util.Arrays;
import java.util.List;

public class ClusteringAlgorithm {
    protected int[] predictorLabels; // this is only used by the AugmentedKmeans clusterer
    protected int k; // number of clusters, only used by certain algorithms that require k

    protected boolean requirePredictorLabel = false;

    public BiclusteringOutput cluster(SimpleDataSet sigDataset, SimpleDataSet Z) {
        throw new UnsupportedOperationException("cluster needs to be overrided by an inheriting class");
    }

    protected void createAssignments(SimpleDataSet sigDataset, SimpleDataSet Z, BiclusteringOutput output,
                                   int[] joint_designations, int clusters) {
        // this is used for discrete assigment clustering models (ie kmeans, etc) where the assignment is always 100% or 0%

        Matrix A = sigDataset.getDataMatrix();
        List<List<Integer>> row_assignments = output.rowAssignments;
        List<List<Integer>> col_assignments = output.columnAssignments;

        // Clear and initialize assignments
        row_assignments.clear();
        col_assignments.clear();
        for(int c = 0; c < clusters; c++) {
            row_assignments.add(new IntList());
            col_assignments.add(new IntList());
        }

        // Assign points to clusters based on k-means results
        for(int z = 0; z < Z.size(); z++) {
            int clusterIndex = joint_designations[z];

            if(z < A.rows()) {
                // This is a row point
                row_assignments.get(clusterIndex).add(z);
            } else {
                // This is a column point
                col_assignments.get(clusterIndex).add(z - A.rows());
            }
        }

        // Prune empty bi-clusters
        for(int j = row_assignments.size()-1; j >= 0; j--) {
            if(row_assignments.get(j).isEmpty() || col_assignments.get(j).isEmpty()) {
                row_assignments.remove(j);
                col_assignments.remove(j);
            }
        }

        output.rowAssignments = row_assignments;
        output.columnAssignments = col_assignments;
    }

    protected double[][] buildMixtureAssignment(double[][] centroids, SimpleDataSet sigDataset, SimpleDataSet Z,
                                          BiclusteringOutput output, int k, double m) {
        /*
            We want mixture assignments for the following reasons:
            - the selection heuristic prunes smaller biclusters, mixture assignments create bigger biclusters
            - real world malware biclusters tend to overlap rather than be perfectly disjoint
         */

        Matrix A = sigDataset.getDataMatrix();
        List<List<Integer>> row_assignments = output.rowAssignments;
        List<List<Integer>> col_assignments = output.columnAssignments;

        // Clear and initialize assignments
        row_assignments.clear();
        col_assignments.clear();
        for(int c = 0; c < k; c++) {
            row_assignments.add(new IntList());
            col_assignments.add(new IntList());
        }

        // Initialize mixture assignments matrix
        double[][] mixtureAssignment = new double[Z.size()][k];

        // For each point
        for (int i = 0; i < Z.size(); i++) {
            double[] point = Z.getDataPoint(i).getNumericalValues().arrayCopy();
            double sumDistances = 0.0;

            // Calculate squared Euclidean distances to each centroid
            double[] distances = new double[k];
            for (int c = 0; c < k; c++) {
                double dist = 0.0;
                for (int d = 0; d < centroids[c].length; d++) {
                    double diff = point[d] - centroids[c][d];
                    dist += diff * diff;
                }
                // Store inverse distance (closer points should have higher mixture values)
                distances[c] = dist; // Add 1 to avoid division by zero
                sumDistances += distances[c];
            }

            // Calculate fuzzy memberships using the fuzzifier m
            double sum = 0.0;
            for (int c = 0; c < k; c++) {
                double membership = 0.0;
                if (distances[c] == 0.0) {
                    // If point is exactly at a centroid, assign full membership to that cluster
                    for (int j = 0; j < k; j++) {
                        mixtureAssignment[i][j] = (j == c) ? 1.0 : 0.0;
                    }
                    sum = 1.0;
                    break;
                }

                // Calculate membership using the fuzzy c-means formula
                for (int j = 0; j < k; j++) {
                    double ratio = distances[c] / distances[j];
                    membership += Math.pow(ratio, 2.0 / (m - 1));
                }
                if (membership != 0.0) {
                    mixtureAssignment[i][c] = 1.0 / membership;
                    sum += mixtureAssignment[i][c];
                }
            }

            // Normalize if necessary (when point isn't exactly at a centroid)
            if (sum > 0.0 && sum != 1.0) {
                for (int c = 0; c < k; c++) {
                    mixtureAssignment[i][c] /= sum;
                }
            }

            // System.out.println("mixture assignment for index " + i + " -> " + Arrays.toString(mixtureAssignment[i]));
            // System.out.println("mixture distances for index " + i + " -> " + Arrays.toString(distances));
        }

        return mixtureAssignment;
    }

    protected void createMixtureAssignments(SimpleDataSet sigDataset, SimpleDataSet Z, BiclusteringOutput output,
                                            double[][] mixtureAssignment, int clusters)
    {
        // this is used for mixture assignment clustering models (ie GMM, etc) where the assignment to each cluster can be between 0%-100%
        Matrix A = sigDataset.getDataMatrix();
        List<List<Integer>> row_assignments = output.rowAssignments;
        List<List<Integer>> col_assignments = output.columnAssignments;

        //prep label outputs
        row_assignments.clear();
        col_assignments.clear();
        for(int c = 0; c < clusters; c++)
        {
            row_assignments.add(new IntList());
            col_assignments.add(new IntList());
        }

        int n = A.rows();
        double thresh = 1.0/(row_assignments.size()+1);
        for(int z = 0; z < Z.size(); z++)
        {
            double[] assignments = mixtureAssignment[z];

            int assigned = 0;
            for(int k = 0; k < assignments.length; k++)
            {
                if(assignments[k] < thresh)
                    continue;//not happening
                assigned++;
                if(z < A.rows())//maybe add this row
                {
                    row_assignments.get(k).add(z);
                }
                else//maybe add this column
                {
                    col_assignments.get(k).add(z-A.rows());
                }
            }

        }

        //Now we need to prune potential false bi-clusterings that have only features or only rows
        for(int j = row_assignments.size()-1; j >= 0; j--)
        {
            if(row_assignments.get(j).isEmpty() || col_assignments.get(j).isEmpty())
            {
                row_assignments.remove(j);
                col_assignments.remove(j);
            }
        }

        output.rowAssignments = row_assignments;
        output.columnAssignments = col_assignments;
    }

    protected void setPredictorLabels(int[] predictorLabels) {
        this.predictorLabels = predictorLabels;
    }

    protected void setK(int k) {
        this.k = k;
    }
}