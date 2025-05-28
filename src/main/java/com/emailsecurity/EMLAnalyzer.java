package com.emailsecurity;

import javax.mail.*;
import javax.mail.internet.*;
import java.io.File;
import java.util.*;
import java.util.regex.Pattern;
import java.util.regex.Matcher;
import picocli.CommandLine;
import picocli.CommandLine.Command;
import picocli.CommandLine.Parameters;

@Command(name = "eml-analyzer", mixinStandardHelpOptions = true,
        description = "Analyzes .eml files for email security risks")
public class EMLAnalyzer implements Runnable {

    @Parameters(index = "0", description = "Path to the .eml file to analyze", 
               arity = "1")
    private File emlFile;

    public static void main(String[] args) {
        int exitCode = new CommandLine(new EMLAnalyzer()).execute(args);
        System.exit(exitCode);
    }

    @Override
    public void run() {
        try {
            if (!emlFile.exists()) {
                System.err.println("Error: File not found - " + emlFile.getAbsolutePath());
                return;
            }
            
            System.out.println("Analyzing: " + emlFile.getAbsolutePath());
            analyzeEML(emlFile);
        } catch (Exception e) {
            System.err.println("Error analyzing email: " + e.getMessage());
            e.printStackTrace();
        }
    }

    private void analyzeEML(File emlFile) throws Exception {
        Session session = Session.getDefaultInstance(new Properties());
        MimeMessage message = new MimeMessage(session, emlFile.toURI().toURL().openStream());

        System.out.println("\n=== Email Header Analysis ===");
        
        System.out.println("\n[Basic Information]");
        System.out.println("From: " + Arrays.toString(message.getHeader("From")));
        System.out.println("To: " + Arrays.toString(message.getHeader("To")));
        System.out.println("Subject: " + Arrays.toString(message.getHeader("Subject")));
        System.out.println("Date: " + Arrays.toString(message.getHeader("Date")));

        System.out.println("\n[Authentication Results]");
        analyzeAuthentication(message);

        System.out.println("\n[Routing Information]");
        analyzeRouting(message.getHeader("Received"));

        System.out.println("\n[Security Verdict]");
        printVerdict(message);
    }

    private void analyzeAuthentication(MimeMessage message) throws MessagingException {
        String spf = getFirstHeader(message, "Received-SPF");
        String dkim = getFirstHeader(message, "DKIM-Signature");
        String dmarc = getFirstHeader(message, "Authentication-Results");

        System.out.println("SPF: " + (spf != null ? spf : "Not found"));
        System.out.println("DKIM: " + (dkim != null ? "Present" : "Not found"));
        System.out.println("DMARC: " + (dmarc != null ? dmarc : "Not found"));
    }

    private void analyzeRouting(String[] receivedHeaders) {
        if (receivedHeaders == null || receivedHeaders.length == 0) {
            System.out.println("No routing information found");
            return;
        }

        System.out.println("Hop Count: " + receivedHeaders.length);
        for (int i = 0; i < receivedHeaders.length; i++) {
            System.out.println("\nHop #" + (i + 1) + ":");
            String header = receivedHeaders[i];
            System.out.println(header);

            extractIPAddress(header);
        }
    }

    private void extractIPAddress(String header) {
        String ipPattern = "\\b(?:\\d{1,3}\\.){3}\\d{1,3}\\b";
        Pattern pattern = Pattern.compile(ipPattern);
        Matcher matcher = pattern.matcher(header);

        if (matcher.find()) {
            System.out.println("Detected IP: " + matcher.group());
        }
    }

    private void printVerdict(MimeMessage message) throws MessagingException {
        String spf = getFirstHeader(message, "Received-SPF");
        String dkim = getFirstHeader(message, "DKIM-Signature");
        String dmarc = getFirstHeader(message, "Authentication-Results");

        boolean isSpfPass = spf != null && spf.contains("pass");
        boolean isDkimPass = dkim != null;
        boolean isDmarcPass = dmarc != null && dmarc.contains("dmarc=pass");

        System.out.println("SPF Check: " + (isSpfPass ? "PASS" : "FAIL"));
        System.out.println("DKIM Check: " + (isDkimPass ? "PASS" : "FAIL"));
        System.out.println("DMARC Check: " + (isDmarcPass ? "PASS" : "FAIL"));

        boolean isSafe = isSpfPass && isDkimPass && isDmarcPass;
        System.out.println("\nFinal Verdict: " + 
            (isSafe ? "SAFE" : "UNSAFE - Potential security risks detected"));
    }

    private String getFirstHeader(Message message, String headerName) throws MessagingException {
        String[] headers = message.getHeader(headerName);
        return (headers != null && headers.length > 0) ? headers[0] : null;
    }
}
