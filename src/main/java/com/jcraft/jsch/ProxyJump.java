package com.jcraft.jsch;

import java.io.ByteArrayOutputStream;
import java.io.FilterInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InterruptedIOException;
import java.io.OutputStream;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.TimeUnit;
import java.util.function.BooleanSupplier;

/**
 * Carries an SSH connection through one or more direct-tcpip channels, like OpenSSH's
 * {@code ProxyJump} ({@code ssh -J}).
 *
 * <p>
 * Each hop is a separate {@link Session} that uses its own {@code Host} configuration. Explicit
 * host-key constraints set on the target session by the application (a host-key repository, a
 * stricter {@code StrictHostKeyChecking}, or {@code server_host_key}) are also applied to the hops,
 * but a hop's own {@code StrictHostKeyChecking} is never weakened.
 *
 * <p>
 * The whole chain shares one connect deadline: the largest {@code ConnectTimeout} of the target and
 * of every hop. Hops do not each get the full timeout.
 */
public final class ProxyJump implements ReadTimeoutProxy {
  private static final int DEFAULT_PORT = 22;
  private static final String URI_PREFIX = "ssh://";
  // A tunnelled SSH session needs a wider window than port forwarding; OpenSSH uses 2 MiB.
  private static final int CHANNEL_WINDOW_SIZE = 0x200000;
  private static final int CHANNEL_PACKET_SIZE = 0x8000;

  private final Session target;
  private final List<Hop> hops;
  private final List<Session> sessions = new ArrayList<>();
  // Aliases of the sessions whose ProxyJump chains lead to this one; a hop's own ProxyJump is the
  // only way chains recurse, so passing them down explicitly detects loops without thread state.
  private Set<String> ancestors = Collections.emptySet();
  private ChannelProxy destination;

  public ProxyJump(Session target, String specification) throws JSchException {
    this.target = target;
    this.hops = parse(specification);
  }

  @Override
  public void connect(SocketFactory socketFactory, String host, int port, int timeout)
      throws JSchException {
    try {
      Session previous = null;
      for (Hop hop : hops) {
        previous = createHop(hop, previous, socketFactory);
        sessions.add(previous);
      }
      int budget = connectBudget(timeout, sessions);
      long deadline = budget > 0 ? System.nanoTime() + TimeUnit.MILLISECONDS.toNanos(budget) : 0;
      for (Session session : sessions) {
        session.connect(remaining(deadline));
      }
      destination = new ChannelProxy(previous);
      destination.connect(socketFactory, host, port, remaining(deadline));
      // Bound each read of the target handshake; Session replaces this once it is authenticated.
      destination.setReadTimeout(budget);
    } catch (JSchException | RuntimeException e) {
      close();
      throw e;
    }
  }

  Session createHop(Hop hop, Session previous, SocketFactory socketFactory) throws JSchException {
    Session next =
        target.jsch.getSession(hop.user, hop.host, hop.port == 0 ? DEFAULT_PORT : hop.port);
    target.applyExplicitHostKeyPolicyTo(next);
    next.setDaemonThread(target.daemon_thread);
    next.setThreadFactory(target.getThreadFactory());
    if (target.getLogger() != target.jsch.getInstanceLogger()) {
      next.setLogger(target.getLogger());
    }
    if (hop.port != 0) {
      next.setPort(hop.port);
    }
    if (previous != null) {
      // Like ssh -J, only the first hop keeps a ProxyJump of its own Host config.
      next.setProxy(new ChannelProxy(previous));
    } else if (next.getProxy() instanceof ProxyJump) {
      Set<String> chain = new HashSet<>(ancestors);
      chain.add(target.org_host);
      ((ProxyJump) next.getProxy()).setAncestors(chain);
    }
    if (previous == null && socketFactory != null) {
      next.setSocketFactory(socketFactory);
    }
    return next;
  }

  private void setAncestors(Set<String> chain) throws JSchException {
    if (chain.contains(target.org_host)) {
      throw new JSchException("ProxyJump cycle involving " + target.org_host);
    }
    ancestors = Collections.unmodifiableSet(chain);
  }

  /** The largest connect timeout on the path, or 0 if none is set. */
  static int connectBudget(int timeout, List<Session> chain) {
    int budget = timeout;
    for (Session session : chain) {
      budget = Math.max(budget, session.getTimeout());
    }
    return budget;
  }

  private static int remaining(long deadline) throws JSchException {
    if (deadline == 0) {
      return 0;
    }
    long millis = TimeUnit.NANOSECONDS.toMillis(deadline - System.nanoTime());
    if (millis <= 0) {
      throw new JSchException("ProxyJump connect timed out");
    }
    return (int) Math.min(millis, Integer.MAX_VALUE);
  }

  @Override
  public InputStream getInputStream() {
    return destination == null ? null : destination.getInputStream();
  }

  @Override
  public OutputStream getOutputStream() {
    return destination == null ? null : destination.getOutputStream();
  }

  @Override
  public Socket getSocket() {
    return null;
  }

  @Override
  public void setReadTimeout(int timeout) throws JSchException {
    if (timeout < 0) {
      throw new JSchException("invalid timeout value");
    }
    if (destination != null) {
      destination.setReadTimeout(timeout);
    }
  }

  @Override
  public void close() {
    if (destination != null) {
      destination.close();
      destination = null;
    }
    for (int i = sessions.size() - 1; i >= 0; i--) {
      sessions.get(i).disconnect();
    }
    sessions.clear();
  }

  static List<Hop> parse(String specification) throws JSchException {
    if (specification == null || specification.isEmpty()) {
      throw new JSchException("ProxyJump requires at least one host");
    }
    List<Hop> result = new ArrayList<>();
    for (String item : specification.split(",", -1)) {
      try {
        result.add(parseHop(item));
      } catch (IllegalArgumentException e) {
        // The item is redacted and the cause dropped so a password-like value never leaks.
        throw new JSchException(
            "Invalid ProxyJump host: " + redact(item) + " (" + e.getMessage() + ")");
      }
    }
    return Collections.unmodifiableList(result);
  }

  /** Hides everything after a ':' in the user part, which may be a password. */
  static String redact(String item) {
    int start = item.startsWith(URI_PREFIX) ? URI_PREFIX.length() : 0;
    int at = item.lastIndexOf('@');
    int colon = item.indexOf(':', start);
    if (at < start || colon < 0 || colon > at) {
      return item;
    }
    return item.substring(0, colon) + ":***" + item.substring(at);
  }

  private static Hop parseHop(String item) {
    if (item.isEmpty()) {
      throw new IllegalArgumentException("empty host");
    }
    for (int i = 0; i < item.length(); i++) {
      if (Character.isWhitespace(item.charAt(i))) {
        throw new IllegalArgumentException("whitespace");
      }
    }
    return item.startsWith(URI_PREFIX) ? parseUriHop(item.substring(URI_PREFIX.length()))
        : parseHostHop(item);
  }

  /** Parses the part after {@code ssh://}, following OpenSSH's parse_uri(). */
  private static Hop parseUriHop(String rest) {
    int slash = rest.indexOf('/');
    if (slash >= 0 && slash != rest.length() - 1) {
      throw new IllegalArgumentException("URI path is not allowed");
    }
    String authority = slash >= 0 ? rest.substring(0, slash) : rest;
    if (authority.indexOf('?') >= 0 || authority.indexOf('#') >= 0) {
      throw new IllegalArgumentException("URI query or fragment is not allowed");
    }
    int at = authority.lastIndexOf('@');
    String user = null;
    if (at >= 0) {
      String userinfo = authority.substring(0, at);
      int params = userinfo.indexOf(';');
      if (params >= 0) {
        // OpenSSH ignores connection parameters such as ";fingerprint=..."
        userinfo = userinfo.substring(0, params);
      }
      if (userinfo.indexOf(':') >= 0) {
        throw new IllegalArgumentException("passwords are not supported");
      }
      user = percentDecode(userinfo);
    }
    return parseAddress(user, authority.substring(at + 1));
  }

  private static Hop parseHostHop(String item) {
    int at = item.lastIndexOf('@');
    return parseAddress(at < 0 ? null : item.substring(0, at), item.substring(at + 1));
  }

  private static Hop parseAddress(String user, String address) {
    if (user != null && user.isEmpty()) {
      throw new IllegalArgumentException("empty user");
    }
    String host;
    String port = null;
    if (address.startsWith("[")) {
      int end = address.indexOf(']');
      if (end < 0 || (end + 1 < address.length() && address.charAt(end + 1) != ':')) {
        throw new IllegalArgumentException("malformed IPv6 address");
      }
      host = address.substring(1, end);
      if (end + 1 < address.length()) {
        port = address.substring(end + 2);
      }
    } else {
      int colon = address.indexOf(':');
      if (colon != address.lastIndexOf(':')) {
        throw new IllegalArgumentException("IPv6 addresses need brackets");
      }
      host = colon < 0 ? address : address.substring(0, colon);
      if (colon >= 0) {
        port = address.substring(colon + 1);
      }
    }
    if (host.isEmpty()) {
      throw new IllegalArgumentException("empty host");
    }
    return new Hop(user, host, port == null ? 0 : parsePort(port));
  }

  private static int parsePort(String value) {
    int port;
    try {
      port = Integer.parseInt(value);
    } catch (NumberFormatException e) {
      throw new IllegalArgumentException("bad port");
    }
    if (port < 1 || port > 65535) {
      throw new IllegalArgumentException("bad port");
    }
    return port;
  }

  private static String percentDecode(String value) {
    if (value.indexOf('%') < 0) {
      return value;
    }
    ByteArrayOutputStream bytes = new ByteArrayOutputStream();
    int i = 0;
    while (i < value.length()) {
      int percent = value.indexOf('%', i);
      if (percent < 0) {
        percent = value.length();
      }
      byte[] literal = value.substring(i, percent).getBytes(StandardCharsets.UTF_8);
      bytes.write(literal, 0, literal.length);
      if (percent == value.length()) {
        break;
      }
      int hi = percent + 2 < value.length() ? Character.digit(value.charAt(percent + 1), 16) : -1;
      int lo = percent + 2 < value.length() ? Character.digit(value.charAt(percent + 2), 16) : -1;
      if (hi < 0 || lo < 0) {
        throw new IllegalArgumentException("bad percent encoding");
      }
      bytes.write((hi << 4) | lo);
      i = percent + 3;
    }
    return new String(bytes.toByteArray(), StandardCharsets.UTF_8);
  }

  static final class Hop {
    final String user;
    final String host;
    final int port;

    Hop(String user, String host, int port) {
      this.user = user;
      this.host = host;
      this.port = port;
    }
  }

  private static final class ChannelProxy implements ReadTimeoutProxy {
    private final Session previous;
    private ChannelDirectTCPIP channel;
    private TimeoutInputStream in;
    private OutputStream out;

    ChannelProxy(Session previous) {
      this.previous = previous;
    }

    @Override
    public void connect(SocketFactory socketFactory, String host, int port, int timeout)
        throws JSchException {
      ChannelDirectTCPIP opened = (ChannelDirectTCPIP) previous.openChannel("direct-tcpip");
      channel = opened;
      opened.setLocalWindowSizeMax(CHANNEL_WINDOW_SIZE);
      opened.setLocalWindowSize(CHANNEL_WINDOW_SIZE);
      opened.setLocalPacketSize(CHANNEL_PACKET_SIZE);
      opened.setHost(host);
      opened.setPort(port);
      try {
        in = new TimeoutInputStream(opened.getInputStream(),
            () -> opened.isConnected() && !opened.isEOF());
        out = opened.getOutputStream();
        opened.connect(timeout);
        if (!opened.isConnected()) {
          throw new JSchException("Unable to connect ProxyJump channel to " + host);
        }
      } catch (IOException e) {
        close();
        throw new JSchException(e.toString(), e);
      } catch (JSchException | RuntimeException e) {
        close();
        throw e;
      }
    }

    @Override
    public InputStream getInputStream() {
      return in;
    }

    @Override
    public OutputStream getOutputStream() {
      return out;
    }

    @Override
    public Socket getSocket() {
      return null;
    }

    @Override
    public void setReadTimeout(int timeout) throws JSchException {
      if (timeout < 0) {
        throw new JSchException("invalid timeout value");
      }
      if (in != null) {
        in.setTimeout(timeout);
      }
    }

    @Override
    public void close() {
      if (channel != null) {
        channel.disconnect();
        channel = null;
      }
      in = null;
      out = null;
    }
  }

  /**
   * Adds a read timeout to a channel's piped stream, which has none of its own.
   *
   * <p>
   * Waits on the pipe's monitor, which the writer notifies on flush. After consuming data it
   * notifies a writer waiting for space: {@link java.io.PipedInputStream} only does so when a read
   * finds the pipe empty, so without it the writer sleeps for up to a second per full pipe.
   */
  static final class TimeoutInputStream extends FilterInputStream {
    // Bounds a wait whose notification was missed.
    private static final long MAX_WAIT_MILLIS = 100;

    private final BooleanSupplier open;
    private final byte[] singleByte = new byte[1];
    private volatile int timeout;

    TimeoutInputStream(InputStream in, BooleanSupplier open) {
      super(in);
      this.open = open;
    }

    void setTimeout(int timeout) {
      this.timeout = timeout;
    }

    @Override
    public int read() throws IOException {
      int count = read(singleByte, 0, 1);
      return count < 0 ? -1 : singleByte[0] & 0xff;
    }

    @Override
    public int read(byte[] bytes, int offset, int length) throws IOException {
      if (offset < 0 || length < 0 || offset > bytes.length - length) {
        throw new IndexOutOfBoundsException();
      }
      if (length == 0) {
        return 0;
      }
      int readTimeout = timeout;
      if (readTimeout == 0) {
        return in.read(bytes, offset, length);
      }
      long deadline = System.nanoTime() + TimeUnit.MILLISECONDS.toNanos(readTimeout);
      // Holding the pipe's monitor keeps the writer from adding data between the checks below, so
      // an empty pipe on a closed channel really is the end of the stream.
      synchronized (in) {
        while (true) {
          int available = in.available();
          if (available > 0) {
            int count = in.read(bytes, offset, Math.min(length, available));
            in.notifyAll();
            return count;
          }
          if (!open.getAsBoolean()) {
            return -1;
          }
          long remaining = TimeUnit.NANOSECONDS.toMillis(deadline - System.nanoTime());
          if (remaining <= 0) {
            throw new SocketTimeoutException("ProxyJump read timed out");
          }
          try {
            in.wait(Math.min(remaining, MAX_WAIT_MILLIS));
          } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new InterruptedIOException("ProxyJump read interrupted");
          }
        }
      }
    }
  }
}
