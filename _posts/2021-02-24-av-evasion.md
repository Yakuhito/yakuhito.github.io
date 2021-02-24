---
title: 'An Interesting Way to Evade AV'
author: yakuhito
layout: post
permalink: an-interesting-way-to-evade-av
image: /images/av-evasion/virus-total-header.png
category: blog
---

# Introduction

Antivirus Software can't protect you against all kinds of malware. While detection techniques evolve every day, malware authors don't just sit and watch how their binaries get quarantined<!-- *cough* got the COVID pun? *cough*--><!--yes, that was a pun inside a pun explanation-->. In this article, I'll present a (supposedly) new way of avoiding detection. Keep in mind that I'm not an expert, so this article might contain some technical mistakes (if you spot one, please contact me so I can correct it).

<div>
<center><img src="/images/av-evasion/virus-total-fragment.png"></center>
</div>

## The Approach

What if the binary that delivered the virus was not malicious at all? The question seems to be quite stupid, but it isn't. The main idea behind my approach is to take a harmless binary and add some purposedly vulnerable functionality.

For my PoC, I took a maze game I coded a few years ago and added a function that would connect to my server, query the 'latest game version', and receive 4096 bytes back. The 4096 bytes, which are supposedly holding the latest game version, are later copied into a 4000-byte buffer and converted to an integer. Spotted the problem?

Since I copied a 4096-byte array into a 4000-byte one with a vulnerable function (`strcpy` in this example), the app has a potential buffer overflow vulnerability. This vulnerability is, however, only exploitable by me under normal circumstances. My server can choose when to deliver a real game version (e.g. '110') or a 4096-byte payload that will exploit the buffer overflow. I can also make the server deliver different payloads depending on the originating IP address or other connection parameters.

I can already hear you wonder: "Isn't this a software backdoor?". Well, it kind of is. Remember that the program connects to MY server and shouldn't be exploitable by anyone else (in theory). You should be able to hide the vulnerable functionality into a more complex, working application. If you do it well enough, it *might* even fool some people looking to see whether the binary is malicious, such as the ones working for AV vendors. In other words, it's a mini-SolarWinds hack only you can exploit.

I should also mention there's a big downside: you have to write a lot of code. Creating an application is definitely not easy, and having a small codebase would just make the vulnerability stand out. Also, once AV companies flag your binary, you'll probably have to start from scratch.

## Conclusion

Compared to the other articles I've posted here, this one was pretty short. I just wanted to get an idea out there, so I don't see the need for a more in-depth explanation. I still need to test the method out and I certainly don't expect AV companies to just sit and watch. Also, please don't use this approach for malicious purposes.

*now please excuse me but my scholastic aptitude's going to get tested again in less than a month*

Until next time, hack the world.

yakuhito, over.