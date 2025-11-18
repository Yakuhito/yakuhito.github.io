---
title: Offensive Security AWAE/OSWE Review
author: yakuhito
layout: post
permalink: /offsec-awae-oswe-review
image: /images/offsec-awae.png
category: blog
---

## Why?
I recently earned my OSWE. As always, I used the last few days before the exam to read reviews about other people's experiences. I couldn't find many articles about this course, so I decided to write this review.

## My background
I've been in the infosec industry for about one year and a half. I'm a high school student, so all my experience mainly comes from CTFs and HTB. I also hold the OSCP cert, but I wouldn't consider it a prerequisite for this course.

## Prerequisites
AWAE is an advanced-level course, so there are some prerequisites. Most of them are listed on [OffSec's site](https://www.offensive-security.com/awae-oswe/):
<center><img src="/images/awae/prereqs.png"></center>
I need to point out that knowing a scripting language is essential: during the course and the exam, you'll be expected to write code that exploits the vulnerabilities you found. Being familiar with a language like python (and its requests library) will give you a considerable time advantage during the exam. 

## The course
Unlike PWK, the number of lab machines is very small. The manual covers the exploitation of 5 web applications, and that's the number of VMs you'll get access to.

In each chapter, there are some exercices which will help you determine wether you understood the concepts being taught or not. There are also some "extra mile exercices", which are much harder than the normal ones. I highly recommend at least attempting to solve those, as you'll definetly learn something new from each of them.

Even though I didn't manage to finish all the exercices, I think 30 days are more than enough to finish the materials. After all, the result only depends on the amount of practice you put into the skills being thaught. The manual isn't very long and you should finish it in about 3 weeks (without the extra miles) going at a slow pace.

## The exam
Here comes the fun part. The 48-hour hands-on exam is the highlight of the AWAE course. I tried to book my exam when my course was about to end and the nearest date was 2 months from then, so scheduling yours as soon as you get the link is a very good idea.

*Note: Due to Offensive Security's Academic Policy, I'm not allowed to go into much detail here. The things you find below can also be found in some Reddit threads.*

On the exam, you'll be given two VMs running two web apps, each containing an auth bypass and a remote code execution vulnerability. You'll also be given creds for two debug machines which can be used to view the source code of the previously-mentoned apps and debug them. You won't need to copy any application files to your local machine - the debug VMs will have all the tools you need. In order to pass the exam, you need to score 85 out of the 100 possible points.

## Timeline
I once read an OSCP review having one of these and I thought it was cool, so here's my AWAE exam timeline:

### 1st Day
* 12:45 - Connect to the Proctoring Software
* 13:00 - Exam Start
* 13:15 - Found something interesting on Machine 1 (possible auth bypass)
* 15:00 - 15:30 - BREAK
* 17:30 - Continue trying to exploit that 'something'
* 19:30 - 20:00 - BREAK
* 20: 15 - Possible RCE on Machine 1?
* 21:00 - RCE on Machine 1, but still no auth bypass.
* 21:30 - BREAK (dinner + go to sleep)

### Day 2
* 6:15 - Continue exam (I had no alarm set; I don't know why I woke up so early)
* 7:00 - Found another interesting thing on Machine 1
* 7:05 - The vulnerability that I tried to exploit yesterday was a dead end
* 8:30 - Exploit for auth bypass + RCE on Machine 1 working, submitted proofs
* 8:40 - 9:00 - BREAK 
* 9:30 - Possible auth bypass on Machine 2
* 10:25 - 10:40 - BREAK
* 12:15 - Finished exploit code for the auth bypass; works on the exam machine
* 13:40 - 14:20 - BREAK
* 14:35 - Managed to execute a command on Debug Machine 2
* 15:50 - RCE on Machine 2; submitted proofs
* 15:50 - 16:10 - BREAK
* 16:10 - Begin writing report; just realised I had no screenshots
* 18:50 - 19:50 - BREAK
* 23:00 - Finished writing the report, ended my exam 14 hours early

## Exam Tips
* Do NOT try to read all the code. While reading some files from start to bottom might help (e.g. looking at the code that communicates with the database to find possible SQL injections), the whole app will probably have thousands of lines of code and your chances of spotting the vulnerability will be close to none.
* Try to avoid dead ends, as much as possible. If something doesn't work for a long period of time, like the 'interesting thing' I found in the first day, move on and come back only if you didn't find anything else.
* Take regular breaks. While writing this article, I was surprised to see that all the vulnerabilites I uncovered were found only a few minutes after a break.
* Test the app from a blackbox perspective and only look at the source code of the parts that seem interesting (import/export functions, code that handles authentication, etc).
* If the above tip didn't work, try looking at the code from a dev's perspective. Can you find some hidden functionality? Are there any comments? Any unfinished or sloppy code?
* If you write the proctor's display name in the chat, make sure you spell it right. Someone with a handle like yakuhito should know that, but I still misspelled a proctor's username 2 times before getting it right. If he/she is reading this, I'm very sorry.
* Some phrases for telling the proctor that you want to take a break without repeating yourself too much:
   * I want to take a break
   * I am going to take a break
   * I am taking a break
   * I will be taking a break
* Some phrases for telling the proctor that you finished your break and want to resume your exam:
   * I want to resume my exam
   * I am back from my break
   * I am ready to resume my exam
* [Follow me on Twitter](https://twitter.com/yakuhito). This won't help you during the exam, but it would make me very happy.

## Conclusion
AWAE is not an entry-level course. While it is as challenging as you would expect any OffSec course to be, I am the living proof that you can pass it on your 1st attempt. Like the OSCP, the exam feels a lot harder than it is before you take it and a lot easier after you passed it. I really enjoyed going through the the course and taking the exam - which felt like a long, well-made, memorable web CTF. I would recommend this course to anyone who wants to sharpen their skills in web aplication testing - and anyone who likes hard challenges.

Now, if you'll excuse me, I have to catch up with my schoolwork.

Until next time, hack the world.

yakuhito, over.