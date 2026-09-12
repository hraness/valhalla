# Symbiosis prototype

Reference model for typed contracts, obligations, bounded signaling, and
backpressure between Valhalla peers or specialized components. It models safe
state transitions only; it does not provide transport, cryptographic identity,
payment, or a distributed consensus protocol. Signal payloads, queue depth, and
deduplication retention are bounded by the model; contract state is not durable
or authenticated, and delayed signals are not a production settlement log.
