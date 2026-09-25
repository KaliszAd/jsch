package com.jcraft.jsch;

import java.io.File;
import java.util.function.Function;

/** Expands OpenSSH-style percent tokens and environment variables in config paths. */
final class ConfigTokenExpander {
  private ConfigTokenExpander() {}

  /**
   * Expands a leading {@code ~} like OpenSSH, before tokens and environment variables, so a
   * substituted value is never home-expanded. Only the current user's home is known, so
   * {@code ~otheruser} is left as is.
   */
  static String expandPath(String path, Function<Character, String> tokens) throws JSchException {
    int rest = homePrefixLength(path);
    if (rest < 0) {
      return expand(path, tokens, true, false);
    }
    return Util.getSystemProperty("user.home") + expand(path.substring(rest), tokens, true, false);
  }

  static String expandTokens(String value, Function<Character, String> tokens)
      throws JSchException {
    return expand(value, tokens, false, false);
  }

  /** Expands the tokens {@code tokens} knows and keeps every other character sequence as is. */
  static String expandKnownTokens(String value, Function<Character, String> tokens) {
    try {
      return expand(value, tokens, false, true);
    } catch (JSchException e) {
      throw new IllegalStateException(e); // lenient expansion does not throw
    }
  }

  /** Returns the index after a leading "~", "~/", "~\" (Windows) or "~currentuser", else -1. */
  private static int homePrefixLength(String path) {
    if (!path.startsWith("~")) {
      return -1;
    }
    int end = 1;
    while (end < path.length() && !isSeparator(path.charAt(end))) {
      end++;
    }
    if (end == 1) {
      return 1;
    }
    String user = Util.getSystemProperty("user.name");
    return path.substring(1, end).equals(user) ? end : -1;
  }

  private static boolean isSeparator(char ch) {
    return ch == '/' || (File.separatorChar == '\\' && ch == '\\');
  }

  private static String expand(String path, Function<Character, String> tokens, boolean environment,
      boolean lenient) throws JSchException {
    StringBuilder expanded = new StringBuilder();
    for (int i = 0; i < path.length(); i++) {
      char ch = path.charAt(i);
      if (ch == '%') {
        if (i + 1 == path.length()) {
          if (lenient) {
            expanded.append(ch);
            continue;
          }
          throw new JSchException("Incomplete config path token: " + path);
        }
        char token = path.charAt(++i);
        String value = token == '%' ? "%" : tokens.apply(token);
        if (value == null) {
          if (lenient) {
            expanded.append(ch).append(token);
            continue;
          }
          throw new JSchException("Unsupported config path token %" + token);
        }
        expanded.append(value);
      } else if (environment && ch == '$' && i + 1 < path.length() && path.charAt(i + 1) == '{') {
        int end = path.indexOf('}', i + 2);
        if (end < 0) {
          throw new JSchException("Incomplete config path environment variable: " + path);
        }
        String name = path.substring(i + 2, end);
        String value = Util.getSystemEnv(name);
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
