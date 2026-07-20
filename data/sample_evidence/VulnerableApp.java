// Deliberately vulnerable sample Java snippet — fixture data for
// core/owasp_security integration tests (pattern-based detection, since
// this project has no Java AST library — docs/adr/0021).
package com.example.demo;

import java.security.MessageDigest;
import java.util.Random;

public class VulnerableApp {
    public void runCommand(String userSuppliedCommand) throws Exception {
        Runtime.getRuntime().exec(userSuppliedCommand);
    }

    public String weakHash(String input) throws Exception {
        MessageDigest digest = MessageDigest.getInstance("MD5");
        return new String(digest.digest(input.getBytes()));
    }

    public int weakRandomToken() {
        Random random = new Random();
        return random.nextInt();
    }
}
