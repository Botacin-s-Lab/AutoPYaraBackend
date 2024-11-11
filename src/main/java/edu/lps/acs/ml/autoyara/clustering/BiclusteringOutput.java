package edu.lps.acs.ml.autoyara.clustering;

import java.util.List;
// Standardized output form for this application
// Standardization is needed to implement multiple selectable algorithms without spaghettification
// BiclusteringOutput is the final output extracted from algorithm selection
// Fields will be public to be accessible by python
public class BiclusteringOutput {
    public List<List<Integer>> rowAssignments;
    public List<List<Integer>> columnAssignments;
}
