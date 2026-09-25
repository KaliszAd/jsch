package com.jcraft.jsch;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTimeoutPreemptively;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayOutputStream;
import java.io.PipedInputStream;
import java.io.PipedOutputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.atomic.AtomicBoolean;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class ProxyJumpTest {
  @TempDir
  Path tempDir;

  @Test
  void parsesHopChain() throws Exception {
    List<ProxyJump.Hop> hops = ProxyJump.parse("alice@corp@first:2222,ssh://bob@[::1]:2200,last");
    assertEquals(3, hops.size());
    assertEquals("alice@corp", hops.get(0).user);
    assertEquals("first", hops.get(0).host);
    assertEquals(2222, hops.get(0).port);
    assertEquals("bob", hops.get(1).user);
    assertEquals("::1", hops.get(1).host);
    assertEquals(2200, hops.get(1).port);
    assertEquals("last", hops.get(2).host);
    assertEquals(0, hops.get(2).port);
  }

  @Test
  void rejectsMalformedHops() {
    for (String value : new String[] {"", "a,,b", "a:", "a:0", "a:65536", "@a", "[::1",
        "ssh://host/path", "a b", "ssh://host:", "ssh://host?x", "ssh://host#x", "ssh://@host",
        "ssh://a:pw@host", "::1", "ssh://a%zz@host"}) {
      assertThrows(JSchException.class, () -> ProxyJump.parse(value), value);
    }
  }

  @Test
  void parsesUriLikeOpenSsh() throws Exception {
    List<ProxyJump.Hop> hops =
        ProxyJump.parse("ssh://a%40b;fingerprint=SHA256:x@bastion_1/,ssh://[fe80::1]");
    assertEquals("a@b", hops.get(0).user);
    assertEquals("bastion_1", hops.get(0).host);
    assertEquals(0, hops.get(0).port);
    assertEquals("fe80::1", hops.get(1).host);
  }

  @Test
  void parseErrorsNeverEchoPasswords() throws Exception {
    for (String value : new String[] {"ssh://alice:s3cret@host", "ssh://alice:s3cret@host:x",
        "alice:s3cret@host:bad"}) {
      JSchException error = assertThrows(JSchException.class, () -> ProxyJump.parse(value));
      assertFalse(error.getMessage().contains("s3cret"), error.getMessage());
      assertTrue(error.getMessage().contains("alice:***@host"), error.getMessage());
      assertEquals(null, error.getCause());
    }
    JSch jsch = new JSch();
    jsch.setConfigRepository(
        OpenSSHConfig.parse("Host target\n  ProxyJump ssh://alice:s3cret@host\n"));
    JSchException error = assertThrows(JSchException.class, () -> jsch.getSession("target"));
    assertFalse(error.getMessage().contains("s3cret"), error.getMessage());
    assertEquals("host", ProxyJump.redact("host"));
    assertEquals("alice@host:22", ProxyJump.redact("alice@host:22"));
  }

  @Test
  void configuresProxyForTargetButNotNone() throws Exception {
    JSch jsch = new JSch();
    jsch.setConfigRepository(OpenSSHConfig.parse(String.join("\n", "Host target",
        "  ProxyJump first,,second", "Host direct", "  ProxyJump none", "")));
    assertThrows(JSchException.class, () -> jsch.getSession("target"));
    assertNotNull(jsch.getSession("direct"));
  }

  @Test
  void detectsRecursiveJumpBeforeOpeningSocket() throws Exception {
    JSch jsch = new JSch();
    jsch.setConfigRepository(OpenSSHConfig.parse("Host loop\n  ProxyJump loop\n"));
    Session session = jsch.getSession("loop");
    JSchException error = assertThrows(JSchException.class, session::connect);
    assertEquals("ProxyJump cycle involving loop", error.getMessage());
    error = assertThrows(JSchException.class, session::connect);
    assertEquals("ProxyJump cycle involving loop", error.getMessage());
  }

  @Test
  void hopKeepsOwnConfigUnlessTargetHasExplicitHostKeyPolicy() throws Exception {
    Path targetKnownHosts = Files.createFile(tempDir.resolve("target_known_hosts"));
    Path jumpKnownHosts = Files.createFile(tempDir.resolve("jump_known_hosts"));
    JSch jsch = new JSch();
    jsch.setConfigRepository(
        OpenSSHConfig.parse(String.join("\n", "Host target", "  ProxyJump jump",
            "  StrictHostKeyChecking yes", "  UserKnownHostsFile " + targetKnownHosts, "Host jump",
            "  StrictHostKeyChecking no", "  UserKnownHostsFile " + jumpKnownHosts, "")));
    Session target = jsch.getSession("target");
    ProxyJump proxy = new ProxyJump(target, "jump");

    Session hop = proxy.createHop(new ProxyJump.Hop(null, "jump", 0), null, null);
    assertEquals("no", hop.getConfig("StrictHostKeyChecking"));
    assertEquals(jumpKnownHosts.toString(), hop.getHostKeyRepository().getKnownHostsRepositoryID());

    HostKeyRepository pinned = new KnownHosts(jsch);
    target.setHostKeyRepository(pinned);
    target.setConfig("StrictHostKeyChecking", "yes");
    target.setConfig("server_host_key", "ssh-ed25519");
    Session pinnedHop = proxy.createHop(new ProxyJump.Hop(null, "jump", 0), null, null);
    assertSame(pinned, pinnedHop.getHostKeyRepository());
    assertEquals("yes", pinnedHop.getConfig("StrictHostKeyChecking"));
    assertEquals("ssh-ed25519", pinnedHop.getConfig("server_host_key"));
  }

  @Test
  void explicitHostKeyCheckingNeverWeakensHop() throws Exception {
    JSch jsch = new JSch();
    jsch.setConfigRepository(OpenSSHConfig.parse(String.join("\n", "Host strict",
        "  StrictHostKeyChecking yes", "Host asking", "  StrictHostKeyChecking ask", "")));
    Session target = jsch.getSession("user", "target");
    ProxyJump proxy = new ProxyJump(target, "strict");

    target.setConfig("StrictHostKeyChecking", "no");
    assertEquals("yes", proxy.createHop(new ProxyJump.Hop(null, "strict", 0), null, null)
        .getConfig("StrictHostKeyChecking"));
    assertEquals("ask", proxy.createHop(new ProxyJump.Hop(null, "asking", 0), null, null)
        .getConfig("StrictHostKeyChecking"));

    target.setConfig("StrictHostKeyChecking", "ask");
    assertEquals("yes", proxy.createHop(new ProxyJump.Hop(null, "strict", 0), null, null)
        .getConfig("StrictHostKeyChecking"));

    target.setConfig("StrictHostKeyChecking", "yes");
    assertEquals("yes", proxy.createHop(new ProxyJump.Hop(null, "asking", 0), null, null)
        .getConfig("StrictHostKeyChecking"));
  }

  @Test
  void hopInheritsThreadSettingsAndLogger() throws Exception {
    JSch jsch = new JSch();
    Session target = jsch.getSession("user", "target");
    ThreadFactory factory = Thread::new;
    Logger logger = new JulLogger();
    target.setDaemonThread(true);
    target.setThreadFactory(factory);
    target.setLogger(logger);
    Session hop =
        new ProxyJump(target, "jump").createHop(new ProxyJump.Hop("u", "jump", 0), null, null);
    assertTrue(hop.daemon_thread);
    assertSame(factory, hop.getThreadFactory());
    assertSame(logger, hop.getLogger());
  }

  @Test
  void chainTimeoutIsLargestOnPathNotSum() throws Exception {
    JSch jsch = new JSch();
    jsch.setConfigRepository(OpenSSHConfig.parse(String.join("\n", "Host three",
        "  ConnectTimeout 3", "Host five", "  ConnectTimeout 5", "")));
    List<Session> chain = new ArrayList<>(Arrays.asList(jsch.getSession("u", "three"),
        jsch.getSession("u", "five"), jsch.getSession("u", "none")));
    assertEquals(5000, ProxyJump.connectBudget(0, chain));
    assertEquals(5000, ProxyJump.connectBudget(1000, chain));
    assertEquals(9000, ProxyJump.connectBudget(9000, chain));
    assertEquals(0, ProxyJump.connectBudget(0, chain.subList(2, 3)));
  }

  @Test
  void silentHopHonorsItsConnectTimeoutWhenTargetHasNone() throws Exception {
    List<Socket> accepted = new ArrayList<>();
    try (ServerSocket silent = new ServerSocket(0, 50, java.net.InetAddress.getLoopbackAddress())) {
      Thread acceptor = new Thread(() -> {
        try {
          while (true) {
            accepted.add(silent.accept());
          }
        } catch (Exception e) {
          // closed
        }
      });
      acceptor.setDaemon(true);
      acceptor.start();
      JSch jsch = new JSch();
      jsch.setConfigRepository(OpenSSHConfig.parse(String.join("\n", "Host silent",
          "  HostName 127.0.0.1", "  Port " + silent.getLocalPort(), "  User u",
          "  ConnectTimeout 1", "Host target", "  User u", "  ProxyJump silent", "")));
      Session target = jsch.getSession("target");
      long start = System.nanoTime();
      assertTimeoutPreemptively(Duration.ofSeconds(10),
          () -> assertThrows(JSchException.class, () -> target.connect(0)));
      assertTrue(System.nanoTime() - start < java.util.concurrent.TimeUnit.SECONDS.toNanos(5));
    } finally {
      for (Socket socket : accepted) {
        socket.close();
      }
    }
  }

  @Test
  void channelStreamHonorsReadTimeoutAndDisconnect() throws Exception {
    AtomicBoolean connected = new AtomicBoolean(true);
    try (PipedInputStream pipe = new PipedInputStream();
        PipedOutputStream writer = new PipedOutputStream(pipe);
        ProxyJump.TimeoutInputStream stream =
            new ProxyJump.TimeoutInputStream(pipe, connected::get)) {
      stream.setTimeout(50);
      assertThrows(SocketTimeoutException.class, stream::read);
      writer.write(42);
      assertEquals(42, stream.read());
      connected.set(false);
      assertEquals(-1, stream.read());
    }
  }

  @Test
  void timedReadDrainsBufferedDataBeforeEndOfStream() throws Exception {
    AtomicBoolean connected = new AtomicBoolean(true);
    try (PipedInputStream pipe = new PipedInputStream();
        PipedOutputStream writer = new PipedOutputStream(pipe);
        ProxyJump.TimeoutInputStream stream =
            new ProxyJump.TimeoutInputStream(pipe, connected::get)) {
      stream.setTimeout(1000);
      writer.write(new byte[] {1, 2, 3});
      connected.set(false);
      byte[] buffer = new byte[8];
      assertEquals(3, stream.read(buffer, 0, buffer.length));
      assertEquals(-1, stream.read());
    }
  }

  @Test
  void timedReadDoesNotStallWriterOnFullPipe() throws Exception {
    byte[] data = new byte[256 * 1024];
    new java.util.Random(1).nextBytes(data);
    try (PipedInputStream pipe = new PipedInputStream(1024);
        PipedOutputStream writer = new PipedOutputStream(pipe);
        ProxyJump.TimeoutInputStream stream = new ProxyJump.TimeoutInputStream(pipe, () -> true)) {
      stream.setTimeout(5000);
      Thread producer = new Thread(() -> {
        try {
          for (int i = 0; i < data.length; i += 4096) {
            writer.write(data, i, 4096);
            writer.flush();
          }
        } catch (Exception e) {
          // reported by the reader timing out
        }
      });
      // Before the fix the writer slept for a second on every full pipe: over 4 minutes here.
      ByteArrayOutputStream received = new ByteArrayOutputStream();
      assertTimeoutPreemptively(Duration.ofSeconds(10), () -> {
        producer.start();
        byte[] buffer = new byte[8192];
        while (received.size() < data.length) {
          received.write(buffer, 0, stream.read(buffer, 0, buffer.length));
        }
      });
      assertArrayEquals(data, received.toByteArray());
    }
  }
}
