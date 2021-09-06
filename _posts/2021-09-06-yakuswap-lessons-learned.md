---
title: yakuSwap - Lessons Learned
author: yakuhito
layout: post
permalink: /yakuSwap-lessons-learned
image: /images/chia-logo.svg
category: blog
---

<br/>

Having a Discord server and listening to my users' suggestions was a very good decision.

If you're reading this, I've succesfully launched yakuSwap version 0.0.4. That number might not tell you much, but I've learned so many things that keeping them for myself would be selfish. Below is a compiled list of ideas that significantly imporved yakuSwap in no particular order - and yes, most of them were suggested by someone on the Discord server.

## DOSing an Entire Blockchain

In Chia, all transactions are stored in an ordered list before being included in a block. This list is called the mempool and the transactions are sorted by - you guessed it - fees. This also applies to all current Chia-based cryptocurrencies.

The initial version of yakuSwap (v0.0.1-BETA) told users to use a fee of one mojo (smallest division of Chia; 1 XCH = 1 trillion mojo). This would grant the transaction 'priority' over most of the others (fees are completely optional). However, I failed to consider one obvious flaw: someone could create billions of transactions with a fee of 2 mojo, thus flooding the blockchain and causing the transaction to not be included in a block for a few days. If they syncronize this attack (which could cost less than $1, especially if done on a fork coin's network) with the moment a party claims the second contract in the trade, a malicious actor could theoretically finish the swap and get both currencies, effectively stealing their partner's money (the attacker would also earn a right to say "Not so atomic now, eh?" with a cowboy accent).

The fix is pretty elegant: instead of putting an arbitrary fee, set each transaction's fee to 1/10000 of the total value - that way, performing the attack would cost more than the potential reward. As a nice bonus, Chia miners will start earning more fees.

## Patience is a Virtue

A few days after I finished reverse engineering a big part of the Chia wallet to find out how the RPC server & Chialisp work, the Chialisp site started getting updates. Moreover, the Chia team started releasing tutorials about Chialisp and even built a new helper command-line utility - I was even able to add currying to my contract, a feat I wasn't able to achieve before ingesting those resources! While yakuSwap is probably the first community-built app that uses Chialisp, everything could've been much easier if I waited one more week (I have no regrets, though!).

## Screenshots

Someone from the community messaged me asking if they could make a suggestion. They asked for screenshots of the app - it turns out that a lot of people didn't know what yakuSwap actually did. I never tought about including screenshots in the README.md file - that was a brilliant idea!

## Oops

Remember the Chialisp contract I presented in [this article](https://blog.kuhi.to/crypto-sorcery-trading-cryptocurrencies-without-a-trusted-third-party)? This is 'him' now:

{% highlight lisp %}
(mod (
		SECRET_HASH
		AMOUNT
		FEE
		FROM_ADDRESS
		TO_ADDRESS
		YAKUSWAP_ADDRESS
		MAX_BLOCK_HEIGHT
		secret
	)

	(defconstant CREATE_COIN 51)
	(defconstant ASSERT_HEIGHT_RELATIVE 82)
	(defconstant ASSERT_FEE 52)

	(defun-inline get_exchange_fee () 
		(+ (f (divmod (* 7 (- AMOUNT FEE)) 1000)) 1)
	)

	(if (= (sha256 secret) SECRET_HASH)
		(list 
			(list CREATE_COIN YAKUSWAP_ADDRESS (get_exchange_fee))
			(list CREATE_COIN TO_ADDRESS (- AMOUNT FEE (get_exchange_fee)))
			(list ASSERT_FEE FEE)
		)
		(list
			(list CREATE_COIN FROM_ADDRESS (- AMOUNT FEE))
			(list ASSERT_FEE FEE)
			(list ASSERT_HEIGHT_RELATIVE MAX_BLOCK_HEIGHT)
		)
	)
)
{% endhighlight %}

The major change is that there are no more `AGG_SIG_UNSAFE` instructions. I stated in my last article that those instructions were there to bypass a limitation of the Chia wallet software - so what happened?

It was all in my mind. The [commit that made the change to the contract](https://github.com/Yakuhito/yakuSwap-server/commit/c83682434b1d2dce35f1883a592f6d17dbbbeb8e) reads 'thanks matt_howard' - a member of the Chia team who (aside from saying that my work is "very impressive") helped me realize how stupid I was. While testing, I tried passing values such as `0x0`, `None`, and `""` to the aggregate signature parameter, but I never tried giving it an empty aggregate signature, which is `empty_agg_sig: G2Element = AugSchemeMPL.aggregate([])` or `0xc0` followed by a lot of 0s.

A lot of people got worried by the 'unsafe' keywork in the opcode's name, so that commit probably also improved the project's credibility.

# YOLO

I [posted a Tweet](https://twitter.com/yakuh1t0/status/1427245947705335815?s=20) that addressed Bram Cohen, the 'father' of Chia (and BitTorrent). I had hoped he'd view my project and say something about it, but probably my tag got lost among the thousands of notifications he receives daily - still, I don't regret trying and I'm sure I'll get his attention some day.

## README.md Update #2

Apart from the YouTube video explaining how to use yakuSwap (which is so bad it's actually funny - and was also a community suggestion), a member of the Discord server suggested having written instructions on using the software. I've also added a short list of reasons about why someone should use yakuSwap instead of an escrow - I don't know why I hadn't thought about that before.

## Swap Time

The first few releases of the app created contracts that would expire after 24 hours - if someone didn't do their part, all money would be returned after 24 hours. However, I knew that normal swaps would take about 20-25 minutes. A few members suggested that I make the swap time window shorter, so I did exactly that - the funny thing is that I've been telling people to ensure that their partner will be online for the trade, but I chose the 24 hour window thinking about timezones.

Needless to say, the window is now 1 hour, which is probably more than enough for swapping a lot of different cryptocurrencies - not just Chia and Chia forks.

## Simple Trade

I'm pretty sure you've never used yakuSwap, so you'll have to trust me on this one: there are A LOT of things about a trade that need to be set beforehand - the secret hash, block heights, addresses, amounts, fees, and more. The original trade creation screen asked the user for all of these values and warned them if they were too far from the default ones.

If you've designed an app before, you've probably already spotted the issue. A lot of users got overwhelmed by all those parameters which they didn't know the meaning of. As a result, some community members suggested I create a simpler trade screen - and I did! The screen only asks you for a few things and then either calculates some parameters from those or sets them to their default value - but having fewer inputs has significantly improved the app's user experience.

## The Chives Exchange

There are 3 PoST currencies I'm very excited about: Chia, Flax, and Chives. The authors of Chives ensured that Chia plots couldn't be used to mine Chives, so I consider the network to be in its infancy. The developers have some great future plans such as master nodes, but I'm not here to advertise them, so I'll get to the point - I didn't want to list Chives on yakuSwap.

My ethical dilemma was that Chives would be considered 'just another fork' and its price would be very low, which I believed to lead to less excitement around the coin. Don't get me wrong - I've been mining Chives with my colleague for some time and I'm very excited about the crypto's future. Chia was the first currency and Flax was the first Chia fork with a pretty active development team, so I was afraid that the qualities of Chives wouldn't stand out just yet.

Then, in an impressive turn of events, the Chives team announced their own centralized exchange. Ouch. I'm sure it wasn't personal, but their announcement really hurt - it could even compete for a spot in the 'Top 10 Anime Betrayals 2021' video. Needless to say, Chives can now be traded with yakuSwap v0.0.4 (and probably all later versions, time traveler).

## Confirmations

I had a few minutes to spare one day, so I found something to do: ask what the minimum confirmation height should be for Chia on their Keybase server. For context, yakuSwap used 10 confirmations for Chia, 25 for Flax, and 32 for all other currencies. I expected the answer to be 7 - I'm not sure why; I could swear I read that somewhere, but I can't find the source - and the first message told me that 192 confirmations are required (that's a whole hour!!!).

This happened about a week before the 0.0.4 update, so I tagged everyone on the Discord server and told them to not use yakuSwap until the next update (I wanted 0.0.4 to include ETH swaps, so I didn't update the software immediately). After some discussion, I discovered that the real number of confirmations was 32, which would take around 10 minutes.

My initial estimate of 10 wasn't entirely wrong, it was just very optimistic (meaning that the chances of the last 10 block miners colluding are higher than I expected). Anyway, yakuSwap users' security is one of my top priorities, so halting trades was the best course of action.

## Conclusion
Phew. That was certainly a long article to write. I learned a lot of new things while building yakuSwap and the journey has just started - I can't wait to see where it leads me. Next stop: the [Global Chia Hackathon](https://chiahackathon2021.devpost.com/), which luckily started around the same time that I published yakuSwap v0.0.1-BETA (I swear I had no idea at that time, but the timing is just too good to ignore).

That's it - no refrences to *that test* since I didn't register for the August session.

Until next time, hack the world.

yakuhito, over.