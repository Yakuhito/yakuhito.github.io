---
title: So Long, and Thanks for All the Trades
author: yakuhito
layout: post
permalink: /so-long-and-thanks-for-all-the-trades
image: images/tibetswap.jpg
category: blog
---

TibetSwap will not be re-launching. It's not a decision I've made lightly. While considering it, thinking about the journey so far brought me immense joy. So I would like to share TibetSwap's history with you first.

## TibetSwap Through the Years

In 2023, the Chia ecosystem was still young - [dexie](https://dexie.space/markets) just launched, and no decentralized apps existed. In fact, the community was debating whether they could exist at all. As I recall, well over half of the messages I was reading on the topic said decentralized apps simply couldn't exist because Chialisp was too complex to support them.

I know the argument doesn't sound believable in retrospect - at that time, though, it did. Chia Network, Inc. (CNI) was supporting a path to an AMM by collaborating with Hashgreen, a fairly large (at some point, 20+ people) MIT-based team with many PhD students. Still, in 16 months, there was no (public) indication an AMM was anywhere close to being released.

That's where TibetSwap came in. I had been working on an RPC provider for Chia (which would power TibetSwap for a long time until being replaced by Coinset) for multiple months, and I knew just enough to realize that a Turing-complete language _must_ allow an AMM to exist. So I started reading the reference node code and released blockchain primitives to teach myself on-chain programming - it was so early that no docs were available for Chia.

After a few months, on March 2, 2023, I released the `tibet` repository to the [public](https://x.com/TibetSwap/status/1631194967845773312?s=20) ([2nd link](https://x.com/TibetSwap/status/1631458383047061505?s=20)). As you can probably tell from [this thread](https://x.com/yakuhito/status/1631195527374331906?s=20), I was proud and genuinely excited for the project - I'd managed to write code for something a lot of people deemed impossible out of my freshman dorm, after all.

I then reached out to all the CNI engineers I could find to ask them to review the code. That went much better than I'd expected - some of them looked over the architecture and made many useful suggestions. Along with others helping in the early days, they're still in the [Special Thanks section](https://github.com/yakuhito/tibet#special-thanks) of the main repository.

After all the improvements were in, TibetSwap went on testnet CLI-only. The UI was later [released on April 18, 2023](https://x.com/TibetSwap/status/1648140008581394432?s=20), and mainnet was launched [just 6 days after](https://x.com/TibetSwap/status/1650532624711163905?s=20).

As you can imagine, my eyes were glued to the screen over the next few days. I was watching and improving everything as we reached [over 1,800 XCH](https://x.com/TibetSwap/status/1651257564137672704?s=20) (around $75,000 at the time) in just 2 days.

And then, luck had it that Ken ([@fizpawiz](https://x.com/fizpawiz)) was there. He started reviewing the code a bit later than other engineers, but was still extremely thorough. He had been coming up with possible attacks repeatedly. Each time, I would reply why the attack wasn't possible. Until, for one of them, I realized [it was](https://x.com/TibetSwap/status/1651349956060667906?s=20).

That event is well documented in the [post-mortem](https://blog.kuhi.to/tibetswap-v1-post-mortem) that was released soon after, but I cannot overstate how grateful I am for people that decide to responsibly disclose bugs that are found (later, [@Ealrann](https://x.com/Ealrann) and [@splitXCH](https://x.com/splitXCH) helped the project in similar ways - more on that below). Exploits are bad for the project, the community behind it, and the creators - and I would not wish one upon anyone.

Even after a big setback, the work continued. I started creating more detailed resources, seeking additional reviews (shout out to BramV - maxim_goods), and TibetSwap got its own community-funded bug bounty pot. On May 14, 2023, [Toucan987 'formally' joined the team](https://x.com/TibetSwap/status/1657793225036550144?s=20) to help with UI/UX, which was by far my biggest weakness. One day later, [v2 launched](https://x.com/TibetSwap/status/1658129000324292608?s=20) on mainnet.

On September 18, 2023, we [reached](https://x.com/TibetSwap/status/1703736826178220449?s=20) what I call the "wallet peak." We always believed an ecosystem is stronger together, and supporting all 5 wallets that were available at the time was a strong commitment to that idea. This was at a time when the other competing AMM was only supporting one (their) wallet.

On September 28, 2023, we launched the [current UI](https://x.com/TibetSwap/status/1707320395400089949?s=20), which I believe (and hope) the community has come to love since then. This came as a result of the incredible work of [@Toucan987](https://x.com/Toucan987), and I find myself appreciating it even today.

A fairly big pause of public communication followed. It wasn't that we stopped working - in fact, quite the opposite. I had been working on the new version of TibetSwap, which I would come to refer to as v2.5. As I later mentioned [in this post](https://blog.fireacademy.io/p/programmable-coins), this version didn't see the light of day because I realized just how much better v3 could be (over the already-existing v2.5, which I would say was a big leap). I talked more about v3 at [Chia Toronto 2025](https://youtu.be/5EyAoQfhXaQ), and how that led to game-changing primitives for dApps (action layer & slots).

On December 23, 2024, [Sage support](https://x.com/TibetSwap/status/1870992361389781217?s=20) was released. Even though it was late to the wallet game, we were early believers in the project - and, indeed, Sage is now probably the most widely used wallet in the community.

Around the same time, we made the then-optional 0.7% developer fee on swaps mandatory. The fee had not been significant until then, and it had never come close to paying for hosting costs. After the change, fees did begin to accumulate and made their way to the community as bounties, thank-yous, and tips for many reviews of new projects. To this day, I don't think I've personally kept or cashed out any XCH from dev fees.

On February 28, 2025, TibetSwap finally allowed projects to automatically deploy new pairs [through the website](https://github.com/Yakuhito/tibet-ui/commit/bb8e7df4e2fec3d96c8a859cc8921d6c363503a0). Until then, they could only do that through a CLI interface, which meant I helped over 99% of the projects deploy their pairs - that's about 185 deployments in total. I liked the process because it got me talking to an important part of the community, the CAT issuers themselves. For this reason, I only created the 'Deploy' page when I was forced to by the latest wave of new CATs, which had me dropping my work so often that I could barely get anything done for a week - a good problem to have! I kept checking newly deployed projects up until recently, though.

On March 16, 2025, the public CNI filing was released, [and it mentioned TibetSwap!](https://x.com/TibetSwap/status/1901312681488843017?s=20) Reading "The leading automated market maker (AMM) on the Chia blockchain is TibetSwap, which uses funds from liquidity providers to allow anyone to trade XCH and digital assets" was one of my proudest moments, and I've been using "leading AMM" to refer to TibetSwap since.

On September 22, 2025, we opened up the design of [partial offers](https://x.com/TibetSwap/status/1969928604743279100?s=20) to the public, built in (our first) collaboration with CNI. Soon after, on October 4, we also launched [rCAT-XCH pairs](https://x.com/TibetSwap/status/1974337575688286571?s=20).

Recently, on August 25, 2026, we were fortunate that another community member ([@Ealrann](https://x.com/Ealrann)) [found a weakness](https://x.com/TibetSwap/status/2092014706009518333?s=20) in TibetSwap first and disclosed it ethically. 3 years, 3 months, and 23 days after I rescued the [relatively small amount stuck in v1](https://x.com/yakuhito/status/1653284545964421120?s=20), I conducted another rescue and recovered the funds liquidity providers had in v2. More information can be found in the post-mortem posted [here](https://blog.kuhi.to/tibetswap-v2-post-mortem). I also wanted to thank [@splitXCH](https://x.com/splitXCH) for finding another weakness in the design on August 28 and ethically disclosing it.

## Where We Are Now

The week of August 23, with its warp.green hack, the CircuitDAO one, and many other disclosed vulnerabilities was a sign the blockchain landscape is changing very fast. Models have gotten very good at spotting bugs, managing to find them in codebases carefully reviewed by many good auditors (and also scanned with the previous generation). This raises the already high standards needed to run blockchain applications.

After much thinking, I've reached the conclusion that continuing to run TibetSwap responsibly, in this new era, would require much more effort than I can easily give the project. It would not be responsible of me, or fair to you, to simply relaunch and keep running the servers with a hands-off approach. I've also been fortunate enough to have many doors open elsewhere, making the opportunity cost very high.

To me, blockchain is powerful exactly because a motivated person can ship software that will go on to process millions in volume. I'm very proud of how far TibetSwap has come. It has been a true privilege to build and run it, and to be an active part of this amazing community.

So, once again, a heartfelt thank you to all of you.

yakuhito, over.