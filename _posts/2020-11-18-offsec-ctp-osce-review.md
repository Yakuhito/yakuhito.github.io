---
title: Farewell, CTP - One of the Last OSCE Reviews
author: yakuhito
layout: post
permalink: /offsec-ctp-osce-review
image: /images/offsec-osce.png
category: blog
---

## Why?
I recently earned my OSCE. This course might be old, but I still learned a lot of stuff I wouldn't have learned otherwise. I enjoyed the experience so much that I even decided to write a post about it.

## My background
I've been in the infosec industry for about two years. I'm a high school student, so all my experience mainly comes from CTFs and HTB. I also hold the OSCP and OSWE certs, which proved very useful during the course/exam.

## Prerequisites
Well, you're probably not going to register for CTP - I'm not even sure that's possible anymore. However, CTP was intended to be a continuation of the PWK course. It will be replaced with 3 other different courses, each focusing on a different aspect of the original course: web app testing, defense evasion, and exploitation. It goes without saying that these topics are advanced, so basic knowledge in those areas is a must. Also, you should be comfortable with working in Olly, because the majority of the exam is going to be spent doing that. In case you want to take AWAE, the new course for web app pentesting, I recommend reading [my review](/offsec-awae-oswe-review).

## The exam
Ouch. The course might be old, but the exam is, like all other OffSec exams, very hard. You have 48 hours to finish 4 objectives, 2 worth 15 points each and 2 worth 30 points. The maximum score is 90 and you need 75 points to pass. Thankfully, the 30-point objectives can be split into two 'mini-objectives', each having 15 points.

I can't go into much detail here, but just know that none of those objectives were easy. You should expect to learn at least the same amount of information from the exam as you did from the course.

## Timeline
This timeline is rather a description of my exam. I completed a 30-pointer in the first few hours of the exam (thanks, AWAE) and then moved on to the next 30-pointer. I thought it would be as easy as the first one, but it turned out that wasn't the case. By the end of the day, I only finished ~50% of the second 30-point objective.

The next day, I worked on the two 15-point objectives. After finishing them in about 6 hours, I had enough points to pass the exam, so I started writing the report. I finished it around 10.00 PM and decided to use my remaining time to tackle the 30-point objective. I tried different tactics until 6.00 AM then next day, but nothing worked. My exploit would work on the debug machine but not on the target.

## Exam Tips
* This exam is not proctored. Enjoy! Take regular breaks, go for a walk or just spend a few minutes with your family from time to time
* DO NOT PANIC
* Do not underestimate the difficulty of an objective just from its description. I thought the 15-pointers would take me 1 hour to solve, but they actually took 6 hours
* If something doesn't work, just move on to another target and return to it later
* For THE OBJECTIVE, keep an open mind. You can exploit the target in a lot of completely different ways and some might be better than others. You will see what I'm talking about after you pass the exam
* DO NOT PANIC
* [Follow me on Twitter](https://twitter.com/yakuh1t0). This won't help you during the exam, but it would make me very happy.

## Conclusion
After going through the "OSCE Certified" section of the forum, I found out the reason my exploit didn't work. Of course, a silly mistake in my shellcode was to blame. The course material might be oudated, but the course itself and the exam meet the expectations you would have from an OffSec course: they are challenging, hard, but ultimately enjoyable. I can't wait to see the other 2 courses CTP gets replaced with.

Now, if you'll excuse me, I have to prepare for [DECEMBER 5, 2020](https://collegereadiness.collegeboard.org/sat/register/dates-deadlines).

Until next time, hack the world.

yakuhito, over.