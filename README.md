# dnsp - A DNS Proxy

This proxy is designed with three use cases in mind:

1. A local caching and or validating proxy,
2. A load balancer and request router in front of recursive resolvers, and
3. A load balancer in front of authoritative server.

For the first use case, the proxy can be configured to cache DNS replies and
to perform local DNSSEC validation. The proxy can forward requests to the
upstream with the lowest latency.

For the second use case, the proxy can optionally cache or perform DNSSEC 
validation. However, the expected main use case is as a load balancer in
front of a collection of recursive resolvers. Query routing, based in the
requested name can be used to route requests to different servers, for example,
for local names.

The third use case is served by the load balancers and possibly the request
routing.

