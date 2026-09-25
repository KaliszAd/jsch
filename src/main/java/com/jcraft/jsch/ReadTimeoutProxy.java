package com.jcraft.jsch;

interface ReadTimeoutProxy extends Proxy {
  void setReadTimeout(int timeout) throws JSchException;
}
