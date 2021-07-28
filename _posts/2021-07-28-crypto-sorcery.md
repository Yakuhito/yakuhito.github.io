---
title: Crypto Sorcery - Trading Cryptocurrencies Without a Trusted 3rd Party
author: yakuhito
layout: post
permalink: /crypto-sorcery-trading-cryptocurrencies-without-a-trusted-third-party
image: /images/chia-logo.svg
category: blog
---

<br/>

Do you know what I hate most about cryptocurrency exchanges? It's not the fees or having to enter a lot of personal data before being allowed to do anything. It's the fact that they can select which currencies can be traded and which can't.

Even if you follow me on twitter, you probably haven't seen [this tweet](https://twitter.com/yakuh1t0/status/1389180473969098752) (almost nobody did - I still don't know why). For the past few weeks, I've been following and mining Chia, which is a pretty interesting cryptocurrency. This post wasn't made to market it, however, so I'll skip directly to the problem: Chia forks began appearing everywhere, but there's no way to trade them without using an escrow (which is both unsafe and pretty complicated - especially the part where you need to find someone to trade with).

At first, the answer seemed pretty simple: make your own exchange. Truth to be told, I've been thinking about doing that for some time, but there are just too many things you need to do to be able to legally operate a cryptocurrency exchange. Since most of the current exchanges don't even list Chia, I began investigating the third option: trading Chia forks without a trusted third party. Here's how to do it.

## Quick Recap: Blockchain Stuff

A blockchain is just a chain of blocks, each block linking to the previous one. Miners create blocks for a reward and everyone can send their money to any address.

Some blockchains, such as Ethereum's, support smart contracts, which are simple programs that have their own address. When money is sent to that address, the program dictates how that money is spent.

A hash function is a way to compress and distinguish data. The best analogy is a blender: if you blend the same apple 100 times, you get the same 'output'. If you blend a carrot, the output will be very different. However, you cannot reconstruct neither the apples nor the carrot, nor any input for that matter.

## HTLCs

A Hash Time-Locked Contract is a simple type of smart contract. As the name suggests, it is locked by two things: time and a hash. Here's how the contract works:

* When the contract is created, the issuer provides an address that the coins locked in the contract need to be transferred to. The coins will be sent only if someone provides a value that, when hashed, matches a hardcoded hash. (hash lock)
* If the contract is more than n blocks old, all the locked money just returns to the sender. (time lock)

That's pretty much it! This is everything we need to trade two different cryptocurrencies. Keep reading to understand how.

## Atomic cross-chain swaps
An atomic cross-chain swap is a fancy term that describes a trade where two currencies which have different blockchains are swapped with one another without the help of a third party. Phew. That was a really long sentence. Here's how one such trade would take place between Alice and Bob:

1. Alice and Bob meet each other and agree on the cryptocurrencies they want to trade, including the amount. Let's say Alice wants to trade 10 BTC for Bob's 1337 ETH. They also convene on a maximum time period in which the trade can take place, say one day. For convenience, we'll suppose that both blockchains have no transaction fees.
2. Alice creates a trade secret (ALICE-SECRET) and builds a HTLC that locks 10 BTC. The contract includes Bob's BTC address and the hash of the trade secret (5f95416...31c84d2).
3. Bob sees the contract on the Bitcoin blockchain, recognizes it as using a standard HTLC pattern, takes the trade secret hash and issues his own contract on the Ethereum blockchain. This contract locks 1337 ETH and will send those coins to Alice's ETH address only if the trade secret is provided. He uses the same hash, but has no way of knowing the actual secret since only Alice knows it.
4. Alice sees the contract issued by Bob on the Ethereum blockchain and uses the trade secret to get her 1337 ETH by claiming the contract.
5. Since the trade secret was included in the Ethereum blockchain to claim the contract, Bob can see it and use it to claim his 10 BTC.

If Alice doesn't reveal the trade secret, Bob can just wait for one day and reclaim his ETH. If Bob does not issue a valid contract (or doesn't issue one at all), Alice can do the same thing. In the end, Alice and Bob either finish the trade or get their coins back. The only 'wasted' resources (in the worst-case scenario) are transaction fees and the participant's time (1 day).

If you still don't understand and think my writing skills have something to do with that, you can read [this article](https://bcoin.io/guides/swaps.html). If you don't understand something but think I can help, don't hesitate to PM me on Twitter.

## Annoncing yakuSwap

Remember my initial problem about trading Chia and its forks? Well, I am pleased to announce the solution: [yakuSwap](https://github.com/Yakuhito/yakuSwap/) (this is just a temporary name until I find something more fitting). In short, I made an app that makes the whole process easy. It only supports Chia and its forks for now, but that might change in the future. To my knowledge, it's the first unofficial software that uses custom smart contracts - to discover the undocumented functionalities that the app requires, I had to do more source code review than I did during [AWAE](https://blog.kuhi.to/offsec-awae-oswe-review).

Before wrapping up, let me give you an actual example of a HTLC: [the contract used by yakuSwap](https://github.com/Yakuhito/yakuSwap-server/blob/master/contract.clvm).

{% highlight bash %}
(mod (secret)
	(defconstant CREATE_COIN 51)
	(defconstant ASSERT_HEIGHT_RELATIVE 82)
	(defconstant ASSERT_FEE 52)
	(defconstant AGG_SIG_UNSAFE 49)

	(defconstant SECRET_HASH REPLACE_WITH_SECRET_HASH)
	(defconstant AMOUNT REPLACE_WITH_AMOUNT)
	(defconstant FEE REPLACE_WITH_FEE)
	(defconstant FROM_ADDRESS REPLACE_WITH_FROM_ADDRESS)
	(defconstant TO_ADDRESS REPLACE_WITH_TO_ADDRESS)
	(defconstant YAKUSWAP_ADDRESS REPLACE_WITH_YAKUSWAP_ADDRESS)
	(defconstant MAX_BLOCK_HEIGHT REPLACE_WITH_MAX_BLOCK_HEIGHT)

	(defun get_exchange_fee (foo) 
		(+ (f (divmod (* 7 (- AMOUNT FEE)) 1000)) 1)
	)

	(if (= (sha256 secret) SECRET_HASH)
		(list 
			(list CREATE_COIN YAKUSWAP_ADDRESS (get_exchange_fee 1))
			(list CREATE_COIN TO_ADDRESS (- AMOUNT FEE (get_exchange_fee 1)))
			(list ASSERT_FEE FEE)
			(list AGG_SIG_UNSAFE 0xa37901780f3d6a13990bb17881d68673c64e36e5f0ae02922afe9b3743c1935765074d237507020c3177bd9476384a37 "yakuhito")
		)
		(list
			(list CREATE_COIN FROM_ADDRESS (- AMOUNT FEE))
			(list ASSERT_FEE FEE)
			(list ASSERT_HEIGHT_RELATIVE MAX_BLOCK_HEIGHT)
			(list AGG_SIG_UNSAFE 0xa37901780f3d6a13990bb17881d68673c64e36e5f0ae02922afe9b3743c1935765074d237507020c3177bd9476384a37 "yakuhito")
		)
	)
)
{% endhighlight %}

For context, smart contracts in Chia are written in a LISP-like language called Chialisp. Each contract expects some input (the solution) and outputs a list of conditions. For example, a contract can provide a CREATE_COIN condition along with an ASSERT_FEE condition. The former 'sends' coins to another address and the latter only makes the output valid if the remaining coins in the transaction (the 'fee') are equal to a given amount. If the fee is too small or too big, the contract output will be considered invalid and no transaction will happen.

I know you are not familiar with Chialisp, but I'll do my best to explain what the contract does (plus, Chialisp is easy to read; it's only hard to write). The first line tells the compiler to name the first argument passed to the contract 'secret'. There's also a function, `get_exchange_fee`, which returns approximatively 0.7% of the traded amount - that will be sent to an address which I control, if the trade is successful. The next block can be seen as the `main` function and consists of only one if statement. If the hash of the provided secret is equal to a hardcoded value, the coins will be transferred to the target address (there's also a fee to be paid and my 0.7% 'commission', which can be set to 0 by modifying the contract). If the hash of the given value is different, the time lock is 'activated'. The output conditions will send the money back to the contract issuer only if the contract was issued more than n blocks ago, where n is a value negotiated during the initial phase of the trade, usually the average number of blocks created in a 24 hour period.

The `AGG_SIG_UNSAFE` conditions are only there to overcome a limitiation in the Chia wallet software (those source code review skills were really useful!). If you do want to understand them, though, don't hesitate to send me a message.

Well, that's the contract! Making an atomic cross-chain swap is not that hard given you have a contract template such as the one above and a way of meeting trade partners - I will solve the latter problem by having a bot on the [yakuSwap Discord server](https://discord.gg/yNVNvQyYXn).

## Conclusion

I don't know if my latest 'project' disappointed you (sorry!) or impressed you with my blockchain knowledge (Solidity next!), or even if you care at all. I can only say one thing: this crypto sh*t rocks! It's definetly an interesting field and it was really fun to build an app that actually interacts with a decentralized network - even if it's a simple one.

Now, if you’ll excuse me, I have to finish a lot of things before the void will inevitably swallow me and everyone forgets that I ever existed.

Until next time, hack the world.

yakuhito, over.