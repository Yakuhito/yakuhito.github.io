---
title: TibetSwap V1 - Post-Mortem
author: yakuhito
layout: post
permalink: /tibetswap-v1-post-mortem
image: images/tibetswap.jpg
category: blog
---

On April 26th, we confirmed a critical bug in the TibetSwap v1 puzzles. A tweet asking users to withdraw their liquidity was released shortly after, and there is no evidence of the bug being exploited to steal any funds. This article will provide more details on what happened, the bug, and our path going forward.

# What Happened

At 13:57, [fizpawiz](https://twitter.com/fizpawiz) sent me a message on Keybase detailing a possible bug in the code. I saw the message less than 10 minutes later and headed back to my dorm to investigate. In the next hour, I confirmed the bug, chose the best course of action (notice to withdraw + make repository that contains code private), and got in touch with [jde5011](https://twitter.com/jde5011) for advice.

By 15:17, we discussed the strategy and devised an appropriate tweet. [The notice](https://twitter.com/TibetSwap/status/1651349956060667906) was posted at 15:18. Thanks to the collective effort of the Chia community, the word spread quickly, and 50% of the liquidity was withdrawn within the first hour. I closely monitored withdrawals, reviewing errors and assisting people that experienced issues. Two hours after the initial notice, 2/3 of the liquidity was withdrawn. After the first 24 hours, less than 1% of the assets remained in the protocol.

# The Bug

The bug resided in the communication mechanism between the pair singleton and the liquidity TAIL. In short, the two communicate via two announcements for each mint or burn operation. The singleton creates an announcement based on the desired operation ("mint" or "burn"), the CAT's coin id, and the number of tokens being burned or minted. The TAIL then creates an announcement based on the operation being performed - either "mint" or "burn."

While this mechanism is similar to the one `p2_singleton` uses and seems secure initially, [fizpawiz](https://twitter.com/fizpawiz) pointed out a severe flaw. The pair singleton coin id is not included in any of the announcements. As such, an attacker can burn liquidity twice by "locking in" two versions of the pair singleton to the same CAT.

The fix is simple: include the pair coin id in the announcements, thus preventing two singletons from locking onto the same CAT by making sure they produce and consume different announcements for each spend. However, TibetSwap was made to be immutable and have no admin keys, meaning that even the smallest code change requires a new deployment.

# Moving Forward

Security is a top priority for TibetSwap. While the bug is fixed now, we believe the best course of action is to go back to testnet for at least two weeks.

Following the community's advice, we're also starting a bug bounty program! TibetSwap's launcher wallet - [xch1yej80...j0sknl](https://www.spacescan.io/address/xch1yej80zwys9m2kkpch0ywltflxtdyprm2qfd0adwm8ur6qhhnex3qj0sknl) or [TibetSwap.xch](https://tibetswap.xch.cx/) - will be used to hold the funds reserved for payouts. The wallet already contains 200 NAME tokens from NameDAO's [generous grant](https://twitter.com/BenAtreidesVing/status/1631338730693828615?s=20) and 10 XCH that I contributed. The community can donate further funds for bug bounties - if you send something, please [get in touch](https://twitter.com/yakuh1t0) so I can thank you properly!

Lastly, this is an opportunity to be even more transparent. While our code remains open-source, we recognize it may still be challenging to start exploring it. With that in mind, I created a follow-up video to my talk at XCH London, where I discussed the overall design of TibetSwap. The slides, video, and more resources can be found in the new [SECURITY.md file](https://github.com/Yakuhito/tibet/blob/master/SECURITY.md) from the main repository of the project.


# Thanks

First off, please take a few seconds to react to [this tweet](https://twitter.com/TibetSwap/status/1651667211336171520?s=20). Both [fizpawiz](https://twitter.com/fizpawiz) and [jde5011](https://twitter.com/jde5011) deserve infinitely many more kudos than they got, as do the other community members that contributed to TibetSwap V1's development out of the goodness of their hearts, without expecting anything in return. These people are heroes!

Lastly, I would like to end this post by thanking the Chia community. The last week has been crazy. TibetSwap received an incredibly warm welcome and performed beyond my wildest expectations in the two days it was online. After the notice was issued, the Chia community has been nothing but understanding. I am really fortunate to be part of such a fantastic community - thank you!

*now please excuse me but I have to read this article to my pet yak to make sure everything's fine*

Until next time, hack the world.

yakuhito, over.