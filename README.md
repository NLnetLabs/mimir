[![Discuss on Discourse](https://img.shields.io/badge/Discourse-NLnet_Labs-orange?logo=Discourse)](https://community.nlnetlabs.nl/c/dns-libraries-tools/12)
[![Mastodon Follow](https://img.shields.io/mastodon/follow/114692612288811644?domain=social.nlnetlabs.nl&style=social)](https://social.nlnetlabs.nl/@nlnetlabs)

# mimir - A DNS Proxy

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

