package com.jcraft.jsch;

import java.io.InputStream;
import java.io.OutputStream;
import java.net.Socket;
import java.net.URI;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/** Carries an SSH connection through one or more direct-tcpip channels. */
public final class ProxyJump implements Proxy {
  private static final ThreadLocal<Set<String>> CONNECTING = ThreadLocal.withInitial(HashSet::new);

  private final Session target;
  private final List<Hop> hops;
  private final List<Session> sessions = new ArrayList<>();
  private ChannelDirectTCPIP channel;
  private InputStream in;
  private OutputStream out;

  public ProxyJump(Session target, String specification) throws JSchException {
    this.target = target;
    this.hops = parse(specification);
  }

  @Override
  public void connect(SocketFactory socketFactory, String host, int port, int timeout)
      throws Exception {
    String key = target.org_host;
    Set<String> connecting = CONNECTING.get();
    if (!connecting.add(key)) {
      throw new JSchException("ProxyJump cycle involving " + key);
    }
    try {
      Session previous = connectHops(socketFactory, timeout);
      connectDestination(previous, socketFactory, host, port, timeout);
    } catch (Exception e) {
      close();
      throw e;
    } finally {
      connecting.remove(key);
      if (connecting.isEmpty()) {
        CONNECTING.remove();
      }
    }
  }

  private Session connectHops(SocketFactory socketFactory, int timeout) throws Exception {
    Session previous = null;
    for (Hop hop : hops) {
      Session next = createHop(hop, previous, socketFactory);
      sessions.add(next);
      next.connect(timeout);
      previous = next;
    }
    return previous;
  }

  private Session createHop(Hop hop, Session previous, SocketFactory socketFactory)
      throws JSchException {
    Session next = target.jsch.getSession(hop.user, hop.host, hop.port == 0 ? 22 : hop.port);
    if (hop.port != 0) {
      next.setPort(hop.port);
    }
    if (previous != null) {
      next.setProxy(new ChannelProxy(previous));
    } else if (socketFactory != null) {
      next.setSocketFactory(socketFactory);
    }
    return next;
  }

  private void connectDestination(Session previous, SocketFactory socketFactory, String host,
      int port, int timeout) throws Exception {
    ChannelProxy finalProxy = new ChannelProxy(previous);
    finalProxy.connect(socketFactory, host, port, timeout);
    channel = finalProxy.channel;
    in = finalProxy.in;
    out = finalProxy.out;
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
  public void close() {
    if (channel != null) {
      channel.disconnect();
      channel = null;
    }
    for (int i = sessions.size() - 1; i >= 0; i--) {
      sessions.get(i).disconnect();
    }
    sessions.clear();
    in = null;
    out = null;
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
        throw new JSchException("Invalid ProxyJump host: " + item, e);
      }
    }
    return Collections.unmodifiableList(result);
  }

  private static Hop parseHop(String item) {
    if (item.isEmpty() || !item.equals(item.trim()) || item.indexOf(' ') >= 0) {
      throw new IllegalArgumentException();
    }
    Hop hop = item.startsWith("ssh://") ? parseUriHop(item) : parseHostHop(item);
    if (hop.host.isEmpty() || (hop.user != null && hop.user.isEmpty())) {
      throw new IllegalArgumentException();
    }
    return hop;
  }

  private static Hop parseUriHop(String item) {
    URI uri = URI.create(item);
    if (!"ssh".equals(uri.getScheme()) || uri.getHost() == null
        || (uri.getRawPath() != null && !uri.getRawPath().isEmpty()) || uri.getRawQuery() != null
        || uri.getRawFragment() != null) {
      throw new IllegalArgumentException();
    }
    String host = uri.getHost();
    if (host.startsWith("[") && host.endsWith("]")) {
      host = host.substring(1, host.length() - 1);
    }
    int port = uri.getPort();
    if (port == 0 || port > 65535) {
      throw new IllegalArgumentException();
    }
    return new Hop(uri.getUserInfo(), host, Math.max(port, 0));
  }

  private static Hop parseHostHop(String item) {
    int at = item.lastIndexOf('@');
    String user = at < 0 ? null : item.substring(0, at);
    String address = item.substring(at + 1);
    if (address.startsWith("[")) {
      int end = address.indexOf(']');
      if (end < 0 || (end + 1 < address.length() && address.charAt(end + 1) != ':')) {
        throw new IllegalArgumentException();
      }
      int port = end + 1 < address.length() ? parsePort(address.substring(end + 2)) : 0;
      return new Hop(user, address.substring(1, end), port);
    }
    int colon = address.indexOf(':');
    if (colon != address.lastIndexOf(':')) {
      throw new IllegalArgumentException();
    }
    String host = colon < 0 ? address : address.substring(0, colon);
    int port = colon < 0 ? 0 : parsePort(address.substring(colon + 1));
    return new Hop(user, host, port);
  }

  private static int parsePort(String value) {
    int port = Integer.parseInt(value);
    if (port < 1 || port > 65535) {
      throw new IllegalArgumentException();
    }
    return port;
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

  private static final class ChannelProxy implements Proxy {
    private final Session previous;
    private ChannelDirectTCPIP channel;
    private InputStream in;
    private OutputStream out;

    ChannelProxy(Session previous) {
      this.previous = previous;
    }

    @Override
    public void connect(SocketFactory socketFactory, String host, int port, int timeout)
        throws Exception {
      channel = (ChannelDirectTCPIP) previous.openChannel("direct-tcpip");
      if (channel == null) {
        throw new JSchException("Unable to open ProxyJump channel");
      }
      channel.setHost(host);
      channel.setPort(port);
      try {
        in = channel.getInputStream();
        out = channel.getOutputStream();
        channel.connect(timeout);
        if (!channel.isConnected()) {
          throw new JSchException("Unable to connect ProxyJump channel to " + host);
        }
      } catch (Exception e) {
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
    public void close() {
      if (channel != null) {
        channel.disconnect();
        channel = null;
      }
      in = null;
      out = null;
    }
  }
}
