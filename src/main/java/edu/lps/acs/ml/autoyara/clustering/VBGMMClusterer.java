package edu.lps.acs.ml.autoyara.clustering;

import edu.lps.acs.ml.autoyara.clustering.BiclusteringOutput;
import jsat.SimpleDataSet;
import jsat.clustering.VBGMM;
import jsat.linear.Matrix;
import jsat.utils.IntList;

import java.util.List;

public class VBGMMClusterer implements ClusteringAlgorithm {
    public BiclusteringOutput cluster(SimpleDataSet sigDataset, SimpleDataSet Z) {
        BiclusteringOutput output = new BiclusteringOutput();

        VBGMM vbgmm = new VBGMM(VBGMM.COV_FIT_TYPE.DIAG);
        int[] joint_designations = vbgmm.cluster(Z, true, null);
        int clusters = 0;
        for(int i : joint_designations)
            clusters = Math.max(clusters, i);
        clusters++;

        createAssignments(sigDataset, Z, output, vbgmm); // note: this will directly modify output object by reference

        return output;
    }

    private void createAssignments(SimpleDataSet sigDataset, SimpleDataSet Z, BiclusteringOutput output, VBGMM vbgmm)
    {
        Matrix A = sigDataset.getDataMatrix();
        List<List<Integer>> row_assignments = output.rowAssignments;
        List<List<Integer>> col_assignments = output.columnAssignments;

        int clusters = vbgmm.mixtureAssignments(Z.getDataPoint(0).getNumericalValues()).length;
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
            double[] assignments = vbgmm.mixtureAssignments(Z.getDataPoint(z).getNumericalValues());

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
