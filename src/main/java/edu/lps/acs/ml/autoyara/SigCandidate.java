/*
 * Derived from the AutoYara project:
 *     https://github.com/FutureComputing4AI/AutoYara
 *
 * Copyright the AutoYara authors. Licensed under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except in
 * compliance with the License. A copy is provided in LICENSE-Apache-2.0.
 *
 * This file has been modified as part of AutoPYaraBackend by Botacin's Lab.
 * See NOTICE for a summary of the modifications.
 */
package edu.lps.acs.ml.autoyara;

import edu.lps.acs.ml.ngram3.alphabet.AlphabetGram;
import edu.lps.acs.ml.ngram3.alphabet.ByteGrams;
import edu.lps.acs.ml.ngram3.alphabet.ShortGrams;

import java.util.*;

/**
 *
 * @author edraff
 */
public class SigCandidate
{
    AlphabetGram signature;
    double b_fp;
    double m_fp;
    Set<Integer> coverage;
    double entropy = -1;

    @Override
    public boolean equals(Object obj)
    {
        return signature.equals(obj);
    }

    @Override
    public int hashCode()
    {
        return signature.hashCode();
    }

    public SigCandidate(AlphabetGram signature, double b_fp, double m_fp, Set<Integer> coverage)
    {
        this.signature = signature;
        this.b_fp = b_fp;
        this.m_fp = m_fp;
        this.coverage = coverage;
    }

    public SigCandidate(Map<String, Object> dict) {
        // called via python to convert the object back
        List<Integer> sigList = (List<Integer>) dict.get("signature");
        String sigType = (String) dict.get("signature_type");
        int sigSize = ((Number) dict.get("signature_size")).intValue();

        AlphabetGram signature;
        if ("ByteGrams".equals(sigType)) {
            signature = new ByteGrams(sigSize);
        } else if ("ShortGrams".equals(sigType)) {
            signature = new ShortGrams(sigSize);
        } else {
            throw new IllegalArgumentException("Unknown signature type: " + sigType);
        }

        for (Integer value : sigList) {
            signature.push(value);
        }

        double b_fp = ((Number) dict.get("b_fp")).doubleValue();
        double m_fp = ((Number) dict.get("m_fp")).doubleValue();
        Set<Integer> coverage = new HashSet<>((List<Integer>) dict.get("coverage"));

        // Call the existing constructor
        this.signature = signature;
        this.b_fp = b_fp;
        this.m_fp = m_fp;
        this.coverage = coverage;

        // Set entropy separately as it's not part of the main constructor
        this.entropy = ((Number) dict.get("entropy")).doubleValue();
    }

    public double getEntropy()
    {
        if(entropy >= 0)
            return entropy;
        else
            return (entropy = sigEntropy(this));
    }

    public static double sigEntropy(SigCandidate a)
    {
        double[] counts = new double[256];
        int wildCards = 0;
        for(int i = 0; i < a.signature.size(); i++)
        {
            int indx = a.signature.getUnsigned(i);
            if(indx < counts.length)
                counts[indx]++;
            else//wild card, lets increment everyone by a partial to smooth it out
                wildCards++;
        }
        double entropy = 0;
        for(double count : counts)
        {
            //add smothing from wild card counts
            count += wildCards/counts.length;
            double p =  count/a.signature.size();

            if(p > 0)
                entropy += -p * Math.log(p)/Math.log(256);

        }
        return 8*entropy;
    }

    public String getSignature() {
        String outString = "SigCandidate";
        for(int i = 0; i < this.signature.size(); i++)
        {
            int index = this.signature.getUnsigned(i);
            outString += " " + index;
        }

        return outString;
    }
    public HashMap<String, Object> ToPythonDict() {
        HashMap<String, Object> dict = new HashMap<>();

        // Update entropy if it hasn't been calculated
        if (this.entropy < 0) {
            this.entropy = sigEntropy(this);
        }

        // Convert signature to list of strings
        List<String> sigList = new ArrayList<>();
        for (int i = 0; i < this.signature.size(); i++) {
            sigList.add(String.valueOf(this.signature.getUnsigned(i)));
        }

        dict.put("signature", sigList);
        dict.put("b_fp", this.b_fp);
        dict.put("m_fp", this.m_fp);
        dict.put("coverage", new ArrayList<>(this.coverage));
        dict.put("entropy", this.entropy);

        return dict;
    }
}
