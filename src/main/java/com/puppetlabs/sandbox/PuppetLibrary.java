package com.puppetlabs.sandbox;

public interface PuppetLibrary {
    String findNode(String nodeName);
    String saveReport(String nodeName, String reportBody);
    String searchFileMetadata(String path);
    String findFileMetadata(String path);
    String findCatalog(String nodeName);
}
