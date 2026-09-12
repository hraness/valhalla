# Transport layer

The steel-thread transport seam now carries bounded opaque frames through an
explicit `Endpoint` API. The relay knows only delivery path and queue limits;
it cannot parse, authorize, or mint capabilities.

This first implementation is deterministic and in-memory so end-to-end tests
stay fast. A real libp2p adapter should implement the same trait next, with
Noise/WebRTC/relay configuration kept outside `vhalla-policy` and
`vhalla-host`.
