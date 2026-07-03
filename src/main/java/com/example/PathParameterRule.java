package com.example;

import java.util.regex.Pattern;

class PathParameterRule {
    private final String placeholder;
    private final Pattern pattern;
    private final boolean pathAware;

    PathParameterRule(String placeholder, Pattern pattern, boolean pathAware) {
        this.placeholder = placeholder;
        this.pattern = pattern;
        this.pathAware = pathAware;
    }

    boolean matches(String pathSegment) {
        return pattern.matcher(pathSegment).matches();
    }

    Pattern pattern() {
        return pattern;
    }

    String placeholder() {
        return placeholder;
    }

    boolean isPathAware() {
        return pathAware;
    }
}
