package com.example;

import java.util.regex.Pattern;

class PathParameterRule {
    private final String placeholder;
    private final Pattern pattern;

    PathParameterRule(String placeholder, Pattern pattern) {
        this.placeholder = placeholder;
        this.pattern = pattern;
    }

    boolean matches(String pathSegment) {
        return pattern.matcher(pathSegment).matches();
    }

    String placeholder() {
        return placeholder;
    }
}
