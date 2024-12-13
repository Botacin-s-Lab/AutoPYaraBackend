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

import java.util.List;

public class SpectralCoClusterPipeline implements BiclusteringPipeline {
    public static SpectralCoClustering.InputNormalization DEFAULT = SpectralCoClustering.InputNormalization.BISTOCHASTIZATION;
    public SpectralCoClustering.InputNormalization inputNormalization = SpectralCoClustering.InputNormalization.BISTOCHASTIZATION;

    public BiclusteringOutput bicluster(SimpleDataSet sigDataset, ClusteringAlgorithm clusterer) {
        //﻿1. Given A, form An = D_1^{−1/2} A D_2^{−1/2}
        Matrix A = sigDataset.getDataMatrix();

        DenseVector R = new DenseVector(A.rows());
        DenseVector C = new DenseVector(A.cols());

        System.out.println("biclustering algorithm: sigDataset has # rows " + A.rows() + " and # columns " + A.cols());

        Matrix A_n = inputNormalization.normalize(A, R, C);

        //﻿2. Compute l = ceil(log2 k) singular vectors of A_n, u2, . . . u_l+1 and v2, . . . v_l+1, and form the matrix Z as in (12)
        int k_max = Math.min(A.rows(), A.cols());
        int l = (int) Math.ceil(Math.log(k_max)/Math.log(2.0));

        //A_n has r rows and c columns. We are going to make a new data matrix Z
        //Z will have (r+c) rows, and l columns.
        SimpleDataSet Z = create_Z_dataset(A_n, l, R, C, inputNormalization);//+1 b/c we are going to skip the first SV

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
        U = new SubMatrix(U, 0, to_skip, U.rows(), l+to_skip);
        V = new SubMatrix(V, 0, to_skip, V.rows(), l+to_skip);
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
