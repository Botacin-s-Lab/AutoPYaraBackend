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

import com.google.common.base.CharMatcher;
import edu.lps.acs.ml.ngram3.NGramGeneric;
import edu.lps.acs.ml.ngram3.alphabet.AlphabetGram;
import edu.lps.acs.ml.ngram3.alphabet.ByteGrams;
import edu.lps.acs.ml.ngram3.alphabet.ShortGrams;
import java.awt.event.KeyEvent;
import java.io.InputStream;
import java.nio.charset.Charset;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 *
 * @author edraff
 */
public class YaraRuleContainerConjunctive
{
    int total_count; // # of file paths scanned
    String name; // rule name
    List<String> extraComments; // comments added at the header section
    List<Set<SigCandidate>> signature_sets = new ArrayList<>(); // sets of conditions
    List<Integer> min_counts = new ArrayList<>(); // for each signature sets, how many must exist in the exe to be flagged

    public HashMap<String, Object> outputDictionary = new HashMap<>();

    public YaraRuleContainerConjunctive(int total_count, String name)
    {
        this.total_count = total_count;
        this.name = name;
        this.extraComments = new ArrayList<>();
    }
    
    public void addSignature(int count, Set<SigCandidate> signature)
    {
        signature_sets.add(signature);
        min_counts.add(count);
    }
    
    /**
     * Returns the minimum number of terms in any sub-rule of this larger yara rule. 
     * For example, (a and b and c and d) or (d and e and f) would return 3. 
     * @return the minimum number of terms in any sub-rule. 
     */
    public int minConjunctionSize()
    {
        return signature_sets.stream().mapToInt(s->s.size()).min().orElse(0);
    }
    
    public void addComment(String comment)
    {
        this.extraComments.add(comment); 
    }
    
    /**
     * 
     * @param input
     * @return true if this yara rule would fire as a match on the given input stream
     */
    public boolean match(InputStream input)
    {
        if(signature_sets.isEmpty())
            return false;
        NGramGeneric ngram = new NGramGeneric();
        ngram.setAlphabetSize(256);
        ngram.setGramSize(signature_sets.get(0).stream().findAny().get().signature.size());
        ngram.setFilterSize((int) 214748383 / 8);
        
        Map<AlphabetGram, Set<Integer>> observed = new HashMap<>();
        for(Set<SigCandidate> set : signature_sets)
        {
            for(SigCandidate cand : set)
                observed.put(cand.signature, new HashSet<>());
        }
        
        //get counts for what n-grams were seen in this data
        ngram.incrementConuts(input, 0, observed);
        
        //Do we have a match?
        for(int group = 0; group < signature_sets.size(); group++)
        {
            Set<SigCandidate> set = signature_sets.get(group);
            int matches_found = set.stream()
                    .mapToInt(sig_component->observed.get(sig_component).size())
                    .sum();
            
            if (matches_found >= min_counts.get(group))
                return true;
        }
        
        return false;
    }

    @Override
    public String toString()
    {
        removeRedundantConditions();

        StringBuilder sb = new StringBuilder();
        sb.append("rule ").append(name).append("\n");
        sb.append("{\n");
        
        for(String comment : extraComments)
        {
            while(comment.endsWith("\n"))
                comment = comment.substring(0, comment.length()-1);
            comment = comment.replaceAll("\n", "\n\t//");
            
            sb.append("\t//").append(comment).append("\n");
        }
        
        Map<SigCandidate, String> sigToName = new HashMap<>();
        for(Set<SigCandidate> sig_set : signature_sets)
            for(SigCandidate s : sig_set)
                if(!sigToName.containsKey(s))
                    sigToName.putIfAbsent(s, "$x" + sigToName.size());
        List<SigCandidate> signatures = new ArrayList<>(sigToName.keySet());
        
        sb.append("\tstrings:\n");
        for(int i = 0; i < signatures.size(); i++)
        {
            //first lets right out a comment for this rule
            SigCandidate sig = signatures.get(i);
            sb.append("\t\t//Benign FP est: ");
            if(sig.b_fp < 0)
                sb.append("<").append(-sig.b_fp);
            else
                sb.append(-sig.b_fp);
            sb.append(" Malicious FP est: ");
            if(sig.m_fp < 0)
                sb.append("<").append(-sig.m_fp);
            else
                sb.append(-sig.m_fp);
            sb.append(" Entropy: ").append(SigCandidate.sigEntropy(sig))
                    .append(" Found in ").append(sig.coverage.size()).append(" files")
                    .append("\n");
            sb.append("\t\t").append(sigToName.get(sig));
            sb.append(" = ");
            sigToYaraString(sb, sig);
            sb.append("\n");
        }
        sb.append("\n");
        sb.append("\t\tcondition:\n");
        for(int i = 0; i < signature_sets.size(); i++)
        {
            if(i != 0)
                sb.append(" or ");
            sb.append("(").append(min_counts.get(i)).append(" of (");
            boolean first= true;
            for(SigCandidate s : signature_sets.get(i))
            {
                if(first)
                    first = false;
                else
                    sb.append(",");
                sb.append(sigToName.get(s));
            }
            sb.append(") )");
            
        }
        sb.append("}");
        return sb.toString();
    }

    /**
     * Conver the given signature candidate into a sub-string for Yara to use within a rule. 
     * <be>
     * The default is to create a byte string that would look like:<br>
     * <code>{6A 40 68 00 30 00 00 6A 14 8D 91}</code>
     * 
     * 
     * @param sb the string builder to insert the string into
     * @param sig the signature to convert into a string
     */
    private void sigToYaraString(StringBuilder sb, SigCandidate sig)
    {
        AlphabetGram g = sig.signature;
        
        
        byte[] byte_values = new byte[g.size()];
        boolean[] is_wild = new boolean[g.size()];
        boolean any_wild = false;
        
        
        for(int j = 0; j < g.size(); j++)
        {
            int val;
            if(g instanceof ByteGrams)
                val = Byte.toUnsignedInt((byte) g.get(j));
            else if(g instanceof ShortGrams)
                val = Short.toUnsignedInt((short) g.get(j));
            else
                val = 1000;///WHAT?
            if (val > 255)//WILD CARD
            {
                any_wild = is_wild[j] = true;
            }
            else
            {
                byte_values[j] = (byte) val;
            }
        }
        
        if(!any_wild && addAsASCII(sb, byte_values))
        {
            //work done in addAsASCII call, so no need for inner loop conent
        }
        else if(!any_wild && addAsASCII_wide(sb, byte_values))
        {
            //work done in addAsASCII_wide call, so no need for inner loop conent
        }
        else//just write out byte values
        {
            sb.append("{ ");
            for(int j = 0; j < byte_values.length; j++)
            {
                if(is_wild[j])
                    sb.append("??");
                else
                    sb.append(String.format("%02X", Byte.toUnsignedInt(byte_values[j])));
                sb.append(" ");//each hex byte needs to have a space after!
            }
            sb.append("} ");
            asStringComment(sb, byte_values);
        }
        
        
        
    }

    /**
     * If the byte values are actually an ASCII printable string, lets use that 
     * instead of the raw byte values. 
     * @param sb the string builder to insert the string into
     * @param sig the signature to convert into a string
     * @return true if the string was added, false if it does not appear to be
     * an ascii string
     */
    private boolean addAsASCII(StringBuilder sb, byte[] byte_values)
    {
        try
        {
            String s = new String(byte_values, Charset.forName("US-ASCII"));
            if(s.length() != byte_values.length)
                return false;
            if(!CharMatcher.ascii().matchesAllOf(s))
                return false;
            for(char c :s.toCharArray())
                if(!isPrintableChar(c))
                    return false;
            //Not sure how to format these two cases in yara, so skip
            if(s.contains("\"") || s.contains("\\") || s.contains("\r"))
                return false;
            //escape ones that I do understand how to put in yara
            s = s.replace("\t", "\\t");
            s = s.replace("\n", "\\n");
            sb.append("\"").append(s).append("\" ascii");
            return true;
        }
        catch(Exception e)
        {
            return false;
        }
    }
    
    /**
     * A ASCII string may be encoded in Unicode format, which this will try and
     * detect. Yara dosn't actually support Unicode, so we only want to do this
     * if it is an ascii string in uicode encoding.
     *
     * @param sb the string builder to insert the string into
     * @param sig the signature to convert into a string
     * @return true if the string was added, false if it does not appear to be
     * an ascii string in unicode
     */
    private boolean addAsASCII_wide(StringBuilder sb, byte[] byte_values)
    {
        try
        {
            String s = new String(byte_values, Charset.forName("UTF-8"));
            if(s.length() != byte_values.length/2)
                return false;
            if(!CharMatcher.ascii().matchesAllOf(s))
                return false;
            for(char c :s.toCharArray())
                if(!isPrintableChar(c))
                    return false;
            //Not sure how to format these two cases in yara, so skip
            if(s.contains("\"") || s.contains("\\") || s.contains("\r"))
                return false;
            //escape ones that I do understand how to put in yara
            s = s.replace("\t", "\\t");
            s = s.replace("\n", "\\n");
            
            sb.append("\"").append(s).append("\" wide");
            return true;
        }
        catch(Exception e)
        {
            return false;
        }
    }
    
    /**
     * Add string 
     * @param sb
     * @param byte_values
     * @return 
     */
    private boolean asStringComment(StringBuilder sb, byte[] byte_values)
    {
        try
        {
            String s_ascii = new String(byte_values, Charset.forName("US-ASCII"));
            String s_uni = new String(byte_values, Charset.forName("UTF-8"));
            
            double uni_printable = 0;
            for(char c :s_uni.toCharArray())
                if(isPrintableChar(c))
                    uni_printable++;
            uni_printable /= s_uni.length();
            
            double ascii_printable = 0;
            for(char c :s_ascii.toCharArray())
                if(isPrintableChar(c))
                    ascii_printable++;
            ascii_printable /= s_ascii.length();
            
            if(Math.max(ascii_printable, uni_printable) < 0.5)
                return false;//Not that much printable content, skip it
            
            String s;
            if(ascii_printable > uni_printable)
                s = s_ascii;
            else
                s = s_uni;
            
            //escape ones that I do understand how to put in yara
            s = s.replace("\t", "\\t");
            s = s.replace("\n", "\\n");
            s = s.replace("\r", "\\r");
            
            // strips off all non-ASCII characters
            s = s.replaceAll("[^\\x00-\\x7F]", "");

            // erases all the ASCII control characters
            s = s.replaceAll("[\\p{Cntrl}&&[^\r\n\t]]", "");

            // removes non-printable characters from Unicode
            s = s.replaceAll("\\p{C}", "");

            
            sb.append("//This might be a string? Looks like:").append(s);
            return true;
        }
        catch(Exception e)
        {
            return false;
        }
    }
    
    public boolean isPrintableChar(char c)
    {
        Character.UnicodeBlock block = Character.UnicodeBlock.of(c);
        return (!Character.isISOControl(c))
                && c != KeyEvent.CHAR_UNDEFINED
                && block != null
                && block != Character.UnicodeBlock.SPECIALS;
    }

    public boolean isEmpty() {
        if (signature_sets.isEmpty())
            return true;



        return false;
    }
    
    public void appendRuleData() {
        outputDictionary.put("rule_string", toString());
        outputDictionary.put("total_files", this.total_count);
        outputDictionary.put("name", this.name);

        Map<SigCandidate, String> sigToName = new HashMap<>();
        for(Set<SigCandidate> sig_set : signature_sets)
            for(SigCandidate s : sig_set)
                if(!sigToName.containsKey(s))
                    sigToName.putIfAbsent(s, "$x" + sigToName.size());

        outputDictionary.put("strings", sigToName.size());

        List<Integer> max_counts = new ArrayList<>();
        for(int i = 0; i < signature_sets.size(); i++)
        {
            max_counts.add(signature_sets.get(i).size());
        }
        outputDictionary.put("conditions_min", this.min_counts);
        outputDictionary.put("conditions_max", max_counts);
    }

    /**
     * Removes redundant conditions from signature_sets and min_counts.
     * A condition is redundant if another condition would match the same or more files.
     */
    private void removeRedundantConditions() {
        // Work with indices to safely remove from both lists
        for (int i = signature_sets.size() - 1; i >= 0; i--) {
            Set<SigCandidate> current = signature_sets.get(i);
            int currentCount = min_counts.get(i);

            // Check if this condition is made redundant by any other condition
            boolean isRedundant = false;
            for (int j = 0; j < signature_sets.size(); j++) {
                if (i == j) continue;

                Set<SigCandidate> other = signature_sets.get(j);
                int otherCount = min_counts.get(j);

                // If other contains subset of signatures and requires fewer matches,
                // then current is redundant
                if (current.containsAll(other) &&
                        otherCount <= currentCount &&
                        otherCount <= other.size()) {
                    isRedundant = true;
                    break;
                }
            }

            if (isRedundant) {
                signature_sets.remove(i);
                min_counts.remove(i);
            }
        }
    }
}
