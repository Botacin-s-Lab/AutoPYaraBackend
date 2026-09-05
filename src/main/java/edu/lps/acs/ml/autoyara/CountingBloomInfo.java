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

import static edu.lps.acs.ml.autoyara.AutoYaraCluster.bloomNameToGramSize;
import java.io.BufferedInputStream;
import java.io.File;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.nio.file.Files;
import java.nio.file.Path;

/**
 *
 * @author rjzak
 */
public class CountingBloomInfo {
    public static void main(String[] args) {
        if (args.length != 1) {
            System.err.println("Missing path to bloom filter file.");
            System.exit(1);
        }
        
        Path bloomPath = new File(args[0]).toPath();
        CountingBloom bloom = null;
        int gram_size = -1;
        try(ObjectInputStream ois = new ObjectInputStream(new BufferedInputStream(Files.newInputStream(bloomPath)))) {
            bloom = (CountingBloom) ois.readObject();
            gram_size = bloomNameToGramSize(bloomPath.getFileName().toString());
        }
        catch (IOException | ClassNotFoundException ex) {
            System.err.println("Failed to read " + bloomPath + ": " + ex.getMessage());
            System.exit(1);
        }
        
        if (bloom == null) {
            System.err.println("Failed to load bloom filter.");
            System.exit(1);
        }
        
        System.out.println("N-Gram size: " + gram_size);
        System.out.println("Number of entries: " + bloom.getNumEntries());
        System.out.println("Divisor: " + bloom.divisor);
        System.out.println("Hash functions: " + bloom.hashSeeds.length);
        System.out.println("Number of slots: " + bloom.counts.length);
        System.out.println("Lowest non-zero count: " + bloom.lowestNonZeroCount());
    }
}
