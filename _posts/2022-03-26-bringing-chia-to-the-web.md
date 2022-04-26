---
title: Twitter Thread - Bringing Chia to the Web
author: yakuhito
layout: post
permalink: /bringing-chia-to-the-web
image: /images/twitter.png
category: blog
---

[Original thread](https://twitter.com/yakuh1t0/status/1507773639554445319)

--

After *a lot* of delays, it's finally time to announce what I've been working on:

Bringing Chia to the Web

--

Let's start with 'why?'. When I was developing yakuSwap, one of my primary goals was to make the app as easy to use as possible. Details about yakuSwap are not relevant to this thread; you just need to know that it required sending Chia and looking for coin spends (transactions)

--

The only wallet available at that time  was the official one, so I built my app on top of it. To interact with the Chia blockchain, I had to use the RPC.

--

The HTTP API was only accessible from localhost and the docs stated that it shouldn't be exposed to the internet. Plus, it required authenticating using keys that were stored in local files.

[Side note: all the things mentioned in this tweet are still valid]

--

That meant that yakuSwap, or any other application built for the Chia blockchain, had to be a binary - it couldn't be a website. The last version of my app contained an executable that would start a website on a local port that users had to access. That was not easy to use at all

--

There was also a security issue. I tried not to connect to the wallet RPC, since doing that would alllow the binary to send any amount of coins to any address. I only used the node RPC and asked the user to send coins to an address when it was necessarry.

--

The app was tested a lot, but I didn't want to risk my users' funds in any way. Letting apps have full access to your coins is a disaster waiting to happen, even if one assumes that there will be no malicious actors at play.

--

The Ethereum community came up with a pretty elegant solution to these issues: web apps. Everyone already has at least one browser installed, so there's no need to download any executable. The UI is fully costumizable and people can be asked to approve each transaction.


--

Okay, so how do we go about doing this? In a perfect universe, the browser would interact directly to a Chia node / wallet, no intermediaries or 3rd party libraries required.

<div>
<center><img src="/images/bringing-chia-to-the-web/1.jpeg"></center>
</div>

--

Unfortunately, the above schematic will never work since the Chia documentation states that 'RPC ports should not be exposed to the internet'. Instead, we need to 'talk' to Chia nodes using the protocol on port 8444.

--

The first problem that arises is that the protocol uses a custom serialization algorithm. It's time to make the first announcement: GreenWeb.js ( [https://github.com/Yakuhito/GreenWeb.js](https://github.com/Yakuhito/GreenWeb.js) ).

GreenWeb is a JavaScript library that attempts to be the web3.js-equivalent for Chia.

--

In short, developers can include GreenWeb.js in their web apps and then start 'using' the Chia blockchain. Currently, the library can be used to fetch data (get balance/blocks/etc). You can also use it to ask the user to send coins/CATs or accept offers with [@goby_app](https://twitter.com/goby_app).

--

Documenta**t**ion: [greenwebjs.readthedocs.io](https://greenwebjs.readthedocs.io)

The main goal is to create a 'wrapper' that allows developers to interact with multiple wallets/node software using the same interface. If a new wallet comes out, devs should be able to support it in their app by adding a few lines of code.

--

Another good example is the problem mentioned previously. Want to interact with a full node? You don't need to worry about the custom serialization part - GreenWeb.js will take care of it for you.

<div>
<center><img src="/images/bringing-chia-to-the-web/2.jpeg"></center>
</div>

--

Unfortunately, making Chia webapps a reality is not that simple either. The second problem with the port 8444 protocol is that it requires connecting to a websocket using a custom certificate to authenticate - browsers don't support that and probably never will.

--

To solve this issue, I had to create Leaflet ( [https://github.com/FireAcademy/Leaflet](https://github.com/FireAcademy/Leaflet) ). It's kind of a proxy between the browser and the full node: it receives connections on port 18444 and forwards them to port 8444 while taking care of the certificate stuff.

<div>
<center><img src="/images/bringing-chia-to-the-web/3.jpeg"></center>
</div>

--

However, that means that people have to run something on top of the wallet software. There's no way of taking advantage of the [already running] thousands of Chia nodes. App developers would have to run and manage their own infra, which is both hard and time-consuming.

--

Time for the second announcement: [@fireacademyio](https://twitter.com/fireacademyio) - a centralized service that provides on-demand access to Leaflet nodes 🔥

<div>
<center><img src="/images/bringing-chia-to-the-web/4.jpeg"></center>
</div>

--

I would argue that a centralized service is better than asking devs to run their own infrastructure:

 - It's quicker: just create an account, generate an API key, and you're good to go
 - I do the heavy lifting: let me worry about the infrastructure

--

 - Scaling: because FireAcademy runs multiple nodes, it can handle sudden spikes in traffic. I also managed to configure Kubernetes to auto-scale
 - Costs: only pay for the traffic that you use

--

Every line of code that powers FireAcademy can be found on GitHub ( [https://github.com/FireAcademy](https://github.com/FireAcademy) ). If centralization really worries you, just run your own FireAcademy clone.

--

BOTH PROJECTS ARE IN ALPHA.

While I tested them, I cannot be 100% sure that everything works as intended. If you spot a bug, don't hesitate to contact me. I'm also always open to suggestions.

--

You've reached the end of this thread. Thanks for sticking around - now go and buidl something awesome!

--

[Original thread](https://twitter.com/yakuh1t0/status/1507773639554445319)