package com.jcraft.jsch;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.nio.file.Path;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class SessionIdentityFileTokenTest {
  @TempDir
  Path tempDir;

  @Test
  void expandsHomeTokenBeforeLoadingIdentity() throws Exception {
    String originalHome = System.getProperty("user.home");
    try {
      System.setProperty("user.home", tempDir.toString());
      JSch jsch = new JSch();
      Path key = tempDir.resolve("id_test");
      KeyPair.genKeyPair(jsch, KeyPair.RSA, 1024).writePrivateKey(key.toString());
      jsch.setConfigRepository(OpenSSHConfig.parse("Host target\n IdentityFile %d/id_test\n"));

      Session session = jsch.getSession("target");
      assertEquals(key.toString(), session.getIdentityRepository().getIdentities().get(0).getName());
      assertEquals(0, jsch.getIdentityRepository().getIdentities().size());
    } finally {
      System.setProperty("user.home", originalHome);
    }
  }

  @Test
  void expandsConnectionTokensAndRejectsUnsupportedOnes() throws Exception {
    JSch jsch = new JSch();
    jsch.setConfigRepository(OpenSSHConfig.parse(
        "Host alias\n HostName real.example\n Port 2222\n User remote\n HostKeyAlias key-alias\n"));
    Session session = jsch.getSession("alias");

    assertEquals("real.example/alias/2222/remote/" + System.getProperty("user.name")
        + "/key-alias/%", ConfigTokenExpander.expandPath("%h/%n/%p/%r/%u/%k/%%",
            session::resolveConfigToken));
    assertThrows(JSchException.class,
        () -> ConfigTokenExpander.expandPath("%i/key", session::resolveConfigToken));
  }

  @Test
  void expandsHostnameAndKnownHostsPath() throws Exception {
    JSch jsch = new JSch();
    jsch.setConfigRepository(OpenSSHConfig.parse("Host alias\n HostName %h.example\n"
        + " UserKnownHostsFile " + tempDir + "/%n-known_hosts\n"));

    Session session = jsch.getSession("alias");
    assertEquals("alias.example", session.host);
    assertEquals(tempDir.resolve("alias-known_hosts").toString(),
        session.getHostKeyRepository().getKnownHostsRepositoryID());
  }

  @Test
  void hostKeyAliasTokenDefaultsToOriginalHost() throws Exception {
    JSch jsch = new JSch();
    jsch.setConfigRepository(OpenSSHConfig.parse("Host alias\n HostName real.example\n"
        + " UserKnownHostsFile " + tempDir + "/%k-known_hosts\n"));

    Session session = jsch.getSession("alias");
    assertEquals(tempDir.resolve("alias-known_hosts").toString(),
        session.getHostKeyRepository().getKnownHostsRepositoryID());
  }

  @Test
  void unsetEnvironmentVariableRejectsTrustStore() throws Exception {
    JSch jsch = new JSch();
    jsch.setConfigRepository(OpenSSHConfig.parse(
        "Host alias\n UserKnownHostsFile ${JSCH_UNSET_KNOWN_HOSTS_TEST_90748}/known_hosts\n"));

    assertThrows(JSchException.class, () -> jsch.getSession("alias"));
  }
}
