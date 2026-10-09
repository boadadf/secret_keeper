# Windows installation and certificate trust

This delivery supports source setup only. Use scripts/setup-dev.ps1. It does not
install a Windows service, modify registry settings, or import certificates.

The proxy generates a per-user CA at startup. Obtain its PUBLIC certificate with
`secret-keeper certificate`. Never distribute mitmproxy-ca.pem (contains private key).
Verify the public certificate fingerprint before trusting it. Trust only on devices
you administer and only with informed authorization.

For VS Code on native Windows, an operator can import the public certificate into
Current User > Trusted Root Certification Authorities using certmgr.msc. Restart
VS Code completely. The CLI-specific extra CA setting may avoid OS trust changes.
Some runtimes use independent stores; test actual clients, do not disable TLS checks.

Record the CA thumbprint. To uninstall trust, remove that exact certificate from
the same store, undo the proxy setting/environment variables, stop the proxy, and
remove its per-user state only when no client requires its CA. Never remove unrelated
root certificates. Certificate rotation and installer-assisted trust management are
not implemented yet.

The state directory includes the CA private key. Restrict its Windows ACL to the
user and authorized administrators. This delivery does not verify or harden Windows
ACLs automatically. Loopback is not authentication: other local users/processes may
reach the listener. Shared machines need additional protection before deployment.
