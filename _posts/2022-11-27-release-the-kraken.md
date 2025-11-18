---
title: RELEASE THE KRAKEN! - The FireAcademy.io Kraken Update
author: yakuhito
layout: post
permalink: /release-the-kraken
image: https://media.giphy.com/media/CDZwopbecAbIc/giphy.gif
category: blog
---

> The reports of my death are greatly exaggerated.
>
> -- <cite>(not) Mark Twain</cite>

# What?

Most people probably thought I left the Chia ecosystem after [FireAcademy.io](https://fireacademy.io) announced it would shut down servers to save costs without mentioning any future plans. For about a week, I thought the best path forward was just to switch my attention to something else. 

Starting something is hard - from convincing a bank teller to open an account for FireAcademy to building a serializer for the wallet protocol when no documentation was available, I faced various challenges. You're not aware of most of them because they are being handled behind the scenes - there's no point in end-users worrying that I can't solve a bug. Back when the announcement was made, challenges just piled up in a way that made it impossible for me to see a way forward that was worth it.

However, as time passed, I realized I could not abandon the Chia community. The technology behind Chia is just incredible. Yes, it's young and small, but we support each other. I was really touched by how many community members saw the message and reached out to help. Namesdao's [Chia Innovation Grant](https://twitter.com/BenAtreidesVing/status/1591946129478123520) is another excellent example. An honorable mention also goes to [Hiya's thread](https://twitter.com/hiya1024/status/1587564927912660993) for saying some things that needed to be said.

Ok, enough old-man rambling speech; let's get back to the main topic of the post: the Kraken update. I've had some ideas about optimizing FireAcademy for a while. As you can probably infer from my GitHub activity, I had a one-week holiday last week (this week for the other Europeans reading this), which I almost entirely spent implementing these ideas. As you'll see, I completely rewrote FireAcademy's business logic and significantly changed Leaflet, its core component. I am 100% confident that the results are worth it - they are unexpectedly awesome. Let's dig right in!

# The New Design

When building Leaflet, I misinterpreted the idea that 'RPCs are not safe to expose to the Internet.' This lead me to predict that dApps will use the wallet protocol. However, as soon as I discovered that anyone could safely use most RPCs, I added RPC support to Leaflet. The first major update is Leaflet's drop of wallet protocol support - it cuts down complexity and increases speed. Plus, no one will use the wallet protocol for their dApps if they can use RPCs.

Another optimization came from the observation that RPC requests were slow. I traced this back to the use of Firestore as a DB (sorry, Google) and the use of Leaflet for business logic. Leaflet should be a proxy, and another application should handle business logic.

Let me introduce the story of the new architecture as a story of two requests. First, there's a request coming from the dashboard. It might get user data or modify an API key - it doesn't matter. This request enters the k8s cluster through the NGINX Ingress Controller, which handles the SSL stuff with the help of cert-manager. The request is then sent to [catchpole](https://github.com/FireAcademy/catchpole/), which hosts the dashboard API. Firebase is used only in two places: to host the dashboard and for user authentication. The other parts are handled by catchpole, which uses a PostgreSQL database and sometimes also interacts with the Stripe API.

Second, there's a request coming for a dApp. Its final destination is one of our running Leaflet instances, but it also enters the cluster via the NGINX Ingress Controller. It is then passed to catchpole, which checks the API key and records the usage. If everything is ok, the request is then forwarded to Leaflet, and the response in returned to the dApp. All pods (applications) are in the same data center and VPC, sometimes even on the same machine, so it all happens so fast that an end-user might think it's only a simple API.

But it's not - both catchpole and Leaflet scale based on demand. They can handle increases in demand efficiently and with no interaction required on my part. By simplifying Leaflet, I also created a more straightforward configuration for the auto-scaler. No more custom metrics are used; scaling happens when the application CPU and/or memory usage reaches a certain threshold, as it should.

Catchpole is at the core of the new design. It has around 1500 lines of Go code, but it handles all the business logic of FireAcademy: Stripe integration, dashboard API, and API key checks. It's a way of separating credit-stuff (e.g., 'Is this API key valid?' and "I need to add x credits to this user's weekly usage") from the services offered (Leaflet access). And it's really fast and lightweight.

# Results

 * Price: The optimization of Leaflet allowed me to decrease costs 20x. A single RPC request costs 420 credits, down from 8400 'traffic' (which also means credits but is more confusing).
 * Speed: The previous configuration had requests that even took 2 seconds to complete. A typical request in the current one should take under 300ms, with most taking less than 150ms. That's what I call a significant improvement!
 * Independence: Before this update, the cluster config explicitly used DigitalOcean load balancers. This meant that the cluster could only be deployed to DigitalOcean. NGINX Ingress Controller is now used, so anyone can deploy the cluster anywhere!
 * Simplicity: Leaflet and the overall k8s config are now much less complex.
 * Flexibility: New services (APIs) can be added extremely easily to FireAcademy's offering - only a few lines of code need to be changed in catchpole, and the API won't have to worry about credit-stuff.
 * User experience: From renaming 'traffic' to 'credits', creating [docs.fireacademy.io](https://docs.fireacademy.io/), and including free credits in the weekly credits limit to making minor UI tweaks, the new release incorporates all the feedback that I've gathered from users.

# Looking Forward

Well, of course I'm looking forward to the future! Moreover, I'm now more aware than ever of the difficulties that developers face in the Chia ecosystem, from monetary ones to just needing a 'you did a great job there' message. With this in mind, I created the [FireAcademy.io Grants Program](https://docs.fireacademy.io/grants) - follow the link to find out more.

I think that's everything I had to say about the update, but don't hesitate to [PM me](https://twitter.com/yakuhito) if you have any questions or suggestions.


*now please excuse me but university is starting tomorrow and I've done no pre-work whatsoever*

Until next time, hack the world.

yakuhito, over.