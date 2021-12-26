---
title: Double-Hash Time-Locked Contracts
author: yakuhito
layout: post
permalink: /double-hash-time-locked-contracts
image: /images/dhtlc.png
category: blog
---

HTLC-based cross-chain swaps take a little bit too long, don't they?

## Intro

If you've met me or seen [my Twitter](https://twitter.com/yakuh1t0) recently, you probably know about yakuSwap. In short, I attempted to enable users to swap cryptocurrencies from two different blockchains in a trustless way. The biggest problem so far is time: it takes a little too long to perform a swap. With DHTLCs, I hope that I can bring the swap period down to 10-20 minutes, depending on the confirmation times of the blockchains involved.

To understand why DHTLCs are better than HTLCs, you need to know why 'original' HTLC-based swaps take so much time. The process involves sending money to a contract, waiting for the transaction confirmation on one blockchain, sending money to a second contract, and then waiting for enough confirmations on the second blockchain (what happens afterward is irrelevant for this example). The order is transaction 1, confirmation 1, transaction 2, confirmation 2. Issuing transaction 2 before confirmation 1 is risky, as is proceeding before confirmation 2. But here's a simple question: What would happen if both transactions could be safely issued at the same time? That way, they could be confirmed in 'parallel', decreasing the time required for this step of a cross-chain atomic swap by around 50%.

To understand how this is possible, let me define what a DHTLC is.

## Double-Hash Time-Locked Contracts

As a recap, here are the rules that I used [when I explained HTLCs](https://blog.kuhi.to/crypto-sorcery-trading-cryptocurrencies-without-a-trusted-third-party):
  * When the contract is created, the issuer provides an address that the coins locked in the contract need to be transferred to. The coins will only be sent if someone provides a value that, when hashed, matches a hard-coded hash. (hash lock)
  * If the contract is more than n blocks old, all the locked money just returns to the sender. (time lock)

A Double-Hash Time-Locked Contract (DHTLC) is very similar to a Hash Time-Locked Contract (or however you want to spell it; the acronym is still HTLC), except for one thing: instead of a hash, the contract uses two hashes to unlock the transaction. The time lock is identical, but the hash lock requires two values whose hashes need to match two hardcoded values.

For clarity, here's the pseudo-code for a DHTLC:

{% highlight python %}
hardcoded_constants = [
  hash1,
  hash2,
  max_block_height,
  from_address,
  to_address
]
arguments = [
  secret1,
  secret2
]

if sha256(secret1) == hash1 and sha256(secret2) == hash2:
  transfer_funds_to(to_address)
else:
  if contract_block_age() >= max_block_height:
    transfer_funds_to(from_address)
  else:
    revert()
{% endhighlight %}

That's pretty easy to understand, right? However, a double-hash lock does not tell the whole story. To understand how the two contracts can be funded at the same time, you'll have to read the next example.

## A DHTLC-based Cross-Chain Atomic Swap

Let's say that Alice and Bob want to make a cross-chain atomic swap. Here's how a DHTLC-based one would work:
 * Alice finds Bob and they settle the transaction terms: the two currencies involved, their respective amounts, and four addresses, one per blockchain per party. Alice and Bob will also generate one secret each (Alice - secret A, Bob - secret B) and exchange their hashes, hash A and hash B. It doesn't matter if the information is exchanged on-chain or off-chain, as long as it reaches both parties. For this trade, we'll call Bob the 'revealer' (more on that later).
 * Both parties lock the agreed amount in DHTLCs. The 'from_address' parameter in the pseudo-code above is the sender's address and the 'to_address' parameter is the other party's address on the same blockchain. Bob, who is the revealer, will set his DHTLC 'max_block_height' to the number of blocks equivalent to 15 minutes. Alice will set her DHTLC's timeout to the equivalent of 20 minutes, which is Bob's value plus 5 minutes (this is just an example, but the revealer always needs to have a smaller 'max_block_height' for his contract).
 * The confirmation time will vary based on the blockchains involved, but, for this example, we'll consider both transactions confirmed after 10 minutes.
 * Bob reveals secret B to Alice, either via on-chain or off-chain channels.
 * Alice verifies that hash(secret B) = hash B and claims Bob's DHTLC using her secret and Bob's. This needs to happen 10 to 15 minutes after the trade has been started.
 * Bob sees that his money was claimed, extracts secret A from the transaction, and claims Alice's DHTLC.

Note that, if any step fails, both parties can just call off the swap by using the contract's time lock. Bob is the revealer - his hash is only secret until both transactions are confirmed. If he reveals it before Alice's transaction has enough confirmations, he risks losing his money. Similarly, Alice will not claim Bob's contract if it wasn't confirmed.

## Potential Improvements
One significant improvement idea [shark0der](https://twitter.com/shark0der) had: Alice's contract (and Bob's, for that matter) could include a small 'prize' given to the person who submits the two secrets ('claims' it). If you've followed the example above, you know that Bob could lose his money if he went offline just as Alice claimed his contract. Alice could wait 5-10 minutes and use the time lock of her contract to receive her money back, even though she claimed Bob's crypto. To overcome this, we could add a 'bot incentive': if anyone claims Alice's contract using the two (now public) secrets, they will be awarded a small amount of money.

## The End?
Nope. There is still a lot of work to be done, funding to be secured, awesome people to be met. This is only the beginning.
<!--
$ # The last post mentioned some hashes. Here's the hidden value:
$ echo 'Double-Hash Time-Locked Contracts - yakuhito' | md5sum
df567e66993d60837854477ad68bb3b6  -
$ echo 'Double-Hash Time-Locked Contracts - yakuhito' | sha256sum 
e528085e1d953a93bc765b3aab4d743ceb4cfef0da0c167145aa7d31944de564  -
$ echo 'Double-Hash Time-Locked Contracts - yakuhito' | sha512sum 
bc4a340a7eda4caee65fded5945a1c8a6560b7bb4ffee2c4bee83b396659d0b2e76246d766f25b6e510ff480826588149e3f20b38d6ccfee9dd34b1fb75fc1a8  -
-->

If you want to support me, make sure you ~~send me some ETH~~ [follow me on Twitter](https://twitter.com/yakuh1t0).

*Note*: Paper wen? Never - I prefer writing blog posts with easy-to-understand examples.

Until next time, hack the world.

yakuhito, over.