package edu.lps.acs.ml.autoyara;

import java.util.List;
// Standardized output form for this application
// Standardization is needed to implement multiple selectable algorithms without spaghettification
// BiclusteringOutput should be allowed to
public class BiclusteringOutput {
    private List<List<Integer>> rowAssignments;
    private List<List<Integer>> columnAssignments;

    public void setRowAssignments(List<List<Integer>> rowAssignments) {
        this.rowAssignments = rowAssignments;
    }

    public void setColumnAssignments(List<List<Integer>> columnAssignments) {
        this.columnAssignments = columnAssignments;
    }

    public List<List<Integer>> getRowAssignments() {
        return rowAssignments;
    }

    public List<List<Integer>> getColumnAssignments() {
        return columnAssignments;
    }
}
