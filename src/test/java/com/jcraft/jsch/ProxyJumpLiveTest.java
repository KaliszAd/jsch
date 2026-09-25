package com.jcraft.jsch;

import static org.junit.jupiter.api.Assertions.assertTrue;

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
}
