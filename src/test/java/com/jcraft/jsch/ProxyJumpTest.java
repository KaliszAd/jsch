package com.jcraft.jsch;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.io.PipedInputStream;
import java.io.PipedOutputStream;
import java.net.SocketTimeoutException;
import java.util.List;
import java.util.concurrent.atomic.AtomicBoolean;
import org.junit.jupiter.api.Test;

class ProxyJumpTest {
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
        "ssh://host/path", "a b"}) {
      assertThrows(JSchException.class, () -> ProxyJump.parse(value), value);
    }
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
}
