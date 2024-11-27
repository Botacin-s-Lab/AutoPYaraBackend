package edu.lps.acs.ml.autoyara.clustering;

import edu.lps.acs.ml.autoyara.clustering.BiclusteringOutput;
import jsat.SimpleDataSet;
import jsat.clustering.VBGMM;
import jsat.linear.Matrix;
import jsat.utils.IntList;

import java.util.Arrays;
import java.util.List;

public class VBGMMClusterer extends ClusteringAlgorithm {
    public BiclusteringOutput cluster(SimpleDataSet sigDataset, SimpleDataSet Z) {
        BiclusteringOutput output = new BiclusteringOutput();

        VBGMM vbgmm = new VBGMM(VBGMM.COV_FIT_TYPE.DIAG);
        int[] joint_designations = vbgmm.cluster(Z, true, null);

        // we don't need to calculate this because we can just read the mixture assignment size of VBGMM
//        int clusters = 0;
//        for(int i : joint_designations)
//            clusters = Math.max(clusters, i);
//        clusters++;

        System.out.println("VBGMM joint designation" + Arrays.toString(joint_designations));

        double[][] assignments = new double[Z.size()][];
        for(int z = 0; z < Z.size(); z++) {
            assignments[z] = vbgmm.mixtureAssignments(Z.getDataPoint(z).getNumericalValues());
        }

        createMixtureAssignments(sigDataset, Z, output, assignments, assignments[0].length); // note: this will directly modify output object by reference

        return output;
    }
}
