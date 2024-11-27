package edu.lps.acs.ml.autoyara.clustering;

import edu.lps.acs.ml.autoyara.clustering.BiclusteringOutput;
import jsat.SimpleDataSet;
import jsat.clustering.VBGMM;
import jsat.linear.Matrix;
import jsat.utils.IntList;

import java.util.List;

public class ClusteringAlgorithm {
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
}
