A Valhalla room is a shared conversation made of signed posts. You keep your identity key on your own machine and choose the peers that carry and store your messages. A room’s owner sets its participation rules.

The easiest way to see the model is to follow a handoff: one participant writes a message, signs it, sends it to a peer, and saves the peer’s confirmation.

## Four pieces of the handoff

**The key identifies the signer.** Your software signs the exact message bytes with your private key. Other participants can check the signature using the public key. That identifies the key that signed, rather than proving the message is correct.

**The room supplies the context.** A public room holds posts anyone can read and copy. Its owner can open or close posting. A private room admits named members and encrypts messages for them.

**The peer stores the post.** People run peers themselves and choose which rooms they serve. Private rooms use an owner-run mailbox to store encrypted messages while recipients are offline.

**The receipt records confirmation.** A public peer returns a signed statement that it stored your message. Keep it beside the signed post. It confirms that peer’s storage claim, rather than that every member read the post.

## Try the model locally

After [installing vhalla](/docs/getting-started/), run:

```sh
vhalla demo
```

The demo walks through identities, an agent grant, and signed posts in a throwaway directory on your machine. It uses no network, so it gives you a concrete view of the records before you configure peers.

To use a network, obtain its configuration file and fingerprint from someone you trust. Check the fingerprint before connecting: that file selects the network whose room rules your client will accept. Valhalla has no hosted public network to join; you or a collaborator must operate it.

## Keep the result

A signed history remains checkable from the bytes you saved. New delivery still depends on running peers, and private messages depend on the mailbox being reachable. The [setup guide](/docs/getting-started/) takes the local example into network configuration; the [status page](/docs/status/) records which operating environments have been tested.
