# Bazel Proxy Relay

Turns out, Bazel uses the Java built-in Proxy handling 
and only supports plain HTTP proxies.

This little app will run as an 
unsecured HTTP proxy on localhost
(thereby preventing unauthorized access from other machines)
and it'll MITMs all SSL connections
(by using a locally trusted CA to sign new hosts)
so that it can rewrite all of the downloads
to go through a user-specified HTTPS proxy.
The HTTPS proxy connection is encrypted
and users can be authorized using URL-embedded username and password
so this combination should be safe enough 
for hosting private build artifacts to be used in Bazel builds.

For the remote HTTPS proxy, I'm using my
[Build Artifact Server](https://github.com/fxtentacle/build-artifact-server)
which among other things also caches all Bazel downloads
so that your build won't break just because 
some transient dependency changed their URL
or is having certificate problems (again).

This project comes with no warranty and no free support.
It works for me. If it works for you, great :)
If not, please fix things yourself ;)
