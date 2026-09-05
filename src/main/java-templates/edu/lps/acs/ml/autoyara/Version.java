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

public class Version {
    public static final String buildTime = "${timestamp}";
    public static final String pomVersion = "${project.version}";
}
