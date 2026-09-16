int32_t start_smtp(int32_t s, char *ip, int32_t port, unsigned char options, char *miscptr, FILE *fp) {
  char *login, *pass, buffer[500], *buf;
  unsigned char buf1[4096];
  unsigned char buf2[4096];

  if ((buf = hydra_receive_line(s)) == NULL)
    return 1;
  if (from64tobits_n((char *)buf1, buf + 4, sizeof(buf1)) < 0)
    return 3;
  buildAuthResponse((tSmbNtlmAuthChallenge *)buf1, (tSmbNtlmAuthResponse *)buf2, 0, login, pass, NULL, NULL);
  to64frombits(buf1, buf2, SmbLength((tSmbNtlmAuthResponse *)buf2));
  sprintf(buffer, "%s\r\n", buf1);
}
