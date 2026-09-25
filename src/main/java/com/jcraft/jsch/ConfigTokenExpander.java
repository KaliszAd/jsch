package com.jcraft.jsch;

import java.util.function.Function;

/** Expands OpenSSH-style percent tokens and environment variables in config paths. */
final class ConfigTokenExpander {
  private ConfigTokenExpander() {}

  static String expandPath(String path, Function<Character, String> tokens) throws JSchException {
    String expanded = expand(path, tokens, true);
    if (expanded.equals("~") || expanded.startsWith("~/")) {
      expanded = System.getProperty("user.home") + expanded.substring(1);
    }
    return expanded;
  }

  static String expandTokens(String value, Function<Character, String> tokens) throws JSchException {
    return expand(value, tokens, false);
  }

  private static String expand(String path, Function<Character, String> tokens, boolean environment)
      throws JSchException {
    StringBuilder expanded = new StringBuilder();
    for (int i = 0; i < path.length(); i++) {
      char ch = path.charAt(i);
      if (ch == '%') {
        if (++i == path.length()) {
          throw new JSchException("Incomplete config path token: " + path);
        }
        char token = path.charAt(i);
        String value = token == '%' ? "%" : tokens.apply(token);
        if (value == null) {
          throw new JSchException("Unsupported config path token %" + token);
        }
        expanded.append(value);
      } else if (environment && ch == '$' && i + 1 < path.length()
          && path.charAt(i + 1) == '{') {
        int end = path.indexOf('}', i + 2);
        if (end < 0) {
          throw new JSchException("Incomplete config path environment variable: " + path);
        }
        String name = path.substring(i + 2, end);
        String value = System.getenv(name);
        if (value == null) {
          throw new JSchException("Undefined config path environment variable: " + name);
        }
        expanded.append(value);
        i = end;
      } else {
        expanded.append(ch);
      }
    }
    return expanded.toString();
  }
}
