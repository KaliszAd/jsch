package com.jcraft.jsch;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfSystemProperty;

class ProxyJumpLiveTest {
  @Test
  @EnabledIfSystemProperty(named = "proxyjump.test.port", matches = "[0-9]+")
  void connectsThroughOneAndTwoHops() throws Exception {
    String port = System.getProperty("proxyjump.test.port");
    String user = System.getProperty("proxyjump.test.user");
    String key = System.getProperty("proxyjump.test.key");
    JSch jsch = new JSch();
    jsch.addIdentity(key);
    jsch.setConfigRepository(
        OpenSSHConfig.parse("Host jump\n  HostName 127.0.0.1\n  Port " + port + "\n  User " + user
            + "\n  StrictHostKeyChecking no\n" + "Host target-one\n  HostName 127.0.0.1\n  Port "
            + port + "\n  User " + user + "\n  StrictHostKeyChecking no\n  ProxyJump jump\n"
            + "Host target-two\n  HostName 127.0.0.1\n  Port " + port + "\n  User " + user
            + "\n  StrictHostKeyChecking no\n  ProxyJump jump,jump\n"));

    for (String name : new String[] {"target-one", "target-two"}) {
      Session session = jsch.getSession(name);
      try {
        session.connect(10000);
        assertTrue(session.isConnected());
      } finally {
        session.disconnect();
      }
    }
  }

  @Test
  @EnabledIfSystemProperty(named = "proxyjump.test.port", matches = "[0-9]+")
  void sharedHopClosesWithTheLastSessionAndReopensForTheNext() throws Exception {
    String port = System.getProperty("proxyjump.test.port");
    String user = System.getProperty("proxyjump.test.user");
    String key = System.getProperty("proxyjump.test.key");
    JSch jsch = new JSch();
    jsch.addIdentity(key);
    jsch.setConfigRepository(OpenSSHConfig.parse("Host jump\n  HostName 127.0.0.1\n  Port " + port
        + "\n  User " + user + "\n  StrictHostKeyChecking no\n"));
    List<Session> hops = new ArrayList<>();
    ProxyJump.SharedHop shared = ProxyJump.share(() -> {
      Session hop = jsch.getSession("jump");
      hops.add(hop);
      return hop;
    });

    Session first = jsch.getSession(user, "127.0.0.1", Integer.parseInt(port));
    Session second = jsch.getSession(user, "127.0.0.1", Integer.parseInt(port));
    for (Session session : new Session[] {first, second}) {
      session.setConfig("StrictHostKeyChecking", "no");
      session.setProxy(shared.proxy());
      session.connect(10000);
    }
    assertEquals(1, hops.size(), "both sessions share one hop");
    assertTrue(shared.isOpen());

    first.disconnect();
    assertTrue(shared.isOpen(), "the hop stays while a session uses it");
    assertTrue(second.isConnected());
    second.disconnect();
    assertFalse(shared.isOpen(), "the last session closed the hop");
    assertFalse(hops.get(0).isConnected());

    Session third = jsch.getSession(user, "127.0.0.1", Integer.parseInt(port));
    third.setConfig("StrictHostKeyChecking", "no");
    third.setProxy(shared.proxy());
    third.connect(10000);
    assertEquals(2, hops.size(), "a later session opened a fresh hop");
    assertTrue(shared.isOpen());
    third.disconnect();
    assertFalse(shared.isOpen());
  }
}
