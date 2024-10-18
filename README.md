# pgproxy

A postgres proxy implementation in Go. Parses the postgres wire protocol and mutates the connection
stream invisibly to clients to perform things like routing, connection pooling, etc.

Upfront goals:

- Connections to "origin databases" should be kept in a fixed size pool, so that serverless clients
  can dial a connection an arbitrary number of times without overwhelming the source database.
- Database routing should be configurable so that connecting to `proxyhost:5432?database=foo` and
  connecting to `proxyhost:5432?database=bar` could result in the TCP stream being directed to
  entirely different origin hosts.
- Proxy can be run as an database authentication sidecar so that client applications can be agnostic
  as to database hosts or credentials -- they could simply send all requests to `localhost:5432` and
  let the proxy handle fetching and inserting the proper credentials into the handshake.

Stretch goals (e.g. the stuff I will never get to):

- Create a configurable mechanism for client-proxy authentication, so that clients can authenticate
  with providers such as AWS IAM.
- Implement the RAFT protocol so that you can run a cluster of pgproxy nodes for high availability.
  The master node would be responsible for assigning itself to whatever floating IP is assigned to
  the cluster upon election.

## Getting Started

Assumes you have a Go toolchain installed.

```
go run . --log-level=DEBUG ./config.json
```
