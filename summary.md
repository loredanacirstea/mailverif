# Summary

in ./forward I am developing a new email protocol for verifiable forwarded emails, where the body of the email remains the same. the purpose is two fold: 1. regardless of how many times an email is forwarded, if headers are not removed, then any receiver can prove the authenticity of the original email (original email can be fully reproduced). 2. additionally, can be optional, each forwarding step can be traced and proven - who forwards an email also adds a signature over the original email and the previous forwarding steps.
The DNS registry exists so that historical DKIM public keys can be retrieved, to be able to verify at any point in time. We do not want a monopoly on historical DNS registries, so each forwarding step may have a different one. this is why it may be a good idea to include this header in the signature (e.g. forward-Signature). The email registry is a registry that may contain user consent information (e.g. if someone agrees that their emails be provably forwarded in this way) and it may be good to include this info (which can change!) in the forward-signature, at each forwarding step, to reflect the state in that moment in time. These registries are to be determined, right now they are placeholders. Give this info, please fix the protocol.

------

This protocol, which we can call the Provable Forwarding Chain (PFC), ensures two things:
1. Original Message Authenticity: The original email, as sent by its author, can be cryptographically verified by the final recipient, no matter how many times it has been
    forwarded.
2. Forwarding Chain Integrity: Each step in the forwarding chain is individually signed, creating a verifiable audit trail of who forwarded the message and when.

The core principle is that the email body is never altered, thus preserving the original DKIM Body Hash (bh). All modifications happen in the headers, and all original
header information is preserved in new, dedicated headers.

---

Protocol Headers

Here are the three new headers required for the PFC protocol. They are added as a set for each forwarding step.

1. Provable-Forward-DKIM-Context
* Purpose: To preserve the exact state of any header that is modified or removed during a forwarding step. This is the key to reconstructing the original email for
    verification.
* When Added: A new instance of this header is added at each forwarding step.
* Fields:
    * i=<instance>: An integer representing the forwarding step (e.g., 1, 2, 3...).
    * original-<header-name>=<value>: A key-value pair for each header that was changed. The key is the original header's name prefixed with original- (e.g.,
        original-From, original-Subject), and the value is the complete, unmodified value of that header before the forwarder altered it.

    Example (for step i=1):
    Provable-Forward-DKIM-Context: i=1; original-From="Joe SixPack <joe@football.example.com>"; original-To="Suzie Q <suzie@shopping.example.net>"; original-Subject="Is
dinner ready?"; original-Message-ID="<20030712040037.46341.5F8J@football.example.com>"

2. Provable-Forward-Signature
* Purpose: The primary signature for a single forwarding step. It attests to the state of the email after the current forwarder has modified it, while also locking in the
    registry information for that step.
* When Added: A new instance is added at each forwarding step.
* What it Signs: It signs a list of headers (h= tag) present in the email at the time of signing, including the Provable-Forward-DKIM-Context for the current step and the
    signature headers from the previous step. It also signs the (unchanged) body via the bh= tag.
* Fields:
    * i=<instance>: The forwarding step number, matching the context header.
    * d=<domain>, s=<selector>, a=<algorithm>, c=<canonicalization>, t=<timestamp>, bh=<body-hash>, b=<signature>: These are standard DKIM-like signature tags.
    * h=<header-list>: A colon-separated list of headers included in the signature. Crucially, for i > 1, this list must include Provable-Forward-Signature and
        Provable-Forward-Seal from instance i-1 to create the chain. Also Provable-DNS-Registry, Provable-Email-Registry for retrieving historical DKIM keys, as specified by the current forwarder and the email consent registry URL/identifier, as specified by the current forwarder.

3. Provable-Forward-Seal
* Purpose: A "chain" signature that validates the integrity of the PFC headers from the current step. It's simpler than the Forward-Signature and primarily serves to link
    the signature chain together, inspired by ARC's ARC-Seal.
* When Added: A new instance is added at each forwarding step.
* What it Signs: It calculates a signature over the full Provable-Forward-Signature header that was just created for the current instance (i).
* Fields:
    * i=<instance>: The forwarding step number.
    * d=<domain>, s=<selector>, a=<algorithm>, t=<timestamp>, b=<signature>: Standard DKIM-like tags.
    * cv=<chain-validation-status>:
        * For i=1, this is none.
        * For i>1, this is pass if the Provable-Forward-Seal from step i-1 validated successfully, otherwise it is fail.

---

The Forwarding and Verification Process

Forwarding Process (Bob forwards an email to Carol)

1. Initial State: Bob has an email from Alice with a valid DKIM-Signature.
2. Modify Headers: Bob's email client changes the From, To, Subject, Date, and Message-ID headers for the forwarded message.
3. Create `Provable-Forward-DKIM-Context`: Bob's client creates a new Provable-Forward-DKIM-Context header (with i=1). It records the original values of all the headers it
    just changed (e.g., original-From, original-Subject).
4. Create `Provable-Forward-Signature`:
    * It creates a new Provable-Forward-Signature header (i=1).
    * It signs the current headers (including the new From, To, etc., the new Provable-Forward-DKIM-Context, and Alice's original DKIM-Signature).
    * It includes the dnsregistry and emailregistry tags with Bob's chosen values.
5. Create `Provable-Forward-Seal`:
    * It creates a new Provable-Forward-Seal header (i=1).
    * It signs the Provable-Forward-Signature header it just generated.
    * It sets cv=none.
6. Send: Bob's client prepends these three new headers (Seal, Signature, Context) to the email and sends it to Carol.

Verification Process (Carol receives the email)

Carol's email client performs two independent verification checks:

Check 1: Verifying the Forwarding Chain Integrity

This confirms the audit trail is unbroken.

1. Start at the Top: Find the Provable-Forward-Seal with the highest instance number, i=n.
2. Verify the Seal: Verify Provable-Forward-Seal (i=n) against the Provable-Forward-Signature (i=n).
3. Verify the Signature: Verify Provable-Forward-Signature (i=n) using the headers listed in its h= tag.
4. Check Chain Validation (`cv`): If i > 1, confirm that cv=pass.
5. Walk Down the Chain: Repeat steps 2-4 for i=n-1, n-2, ..., down to 1. If all signatures and seals validate, the chain is secure.

Check 2: Verifying the Original Email's Authenticity

This confirms the email Alice originally wrote is authentic.

1. Start with Final Headers: Take the set of headers Carol received.
2. Reconstruct Headers:
    * Iterate from the highest instance i=n down to 1.
    * For each i, read the Provable-Forward-DKIM-Context header.
    * For each original-<header-name> tag found, replace the corresponding header in the working set with this preserved original value.
3. Finalize Reconstruction: After processing all context headers, the working set of headers is now identical to the original email's headers. Remove all
    Provable-Forward-* headers.
4. Verify Original DKIM: Perform a standard DKIM verification using the reconstructed headers, the original DKIM-Signature header, and the unchanged email body. It should
    now pass. The public key is retrieved using the d= and s= tags from the original DKIM-Signature.

=========

- same body
- change subject, to, from , cc, bcc -> store prev values in dkim-context
- create forward signature
- create chain i=1 signature

- receive forward
- verify current dkim signature
- reproduce original email with dkim context + remove all headers above i=1
- verify chain: verify last signature (reproduce last forward step email - remove all headers above i=n & replace dkim context) - last to first instance, first instace verifies original DKIM signature, from original email

