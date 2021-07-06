---
title: Offensive Security EXP-301/OSED Review
author: yakuhito
layout: post
permalink: /offsec-exp301-osed-review
image: /images/offsec-osed.png
category: blog
---

## Intro
Unless you've been living without an internet connection for the past few months, you've probably heard of Offensive Security's new course, Windows User Mode Exploit Development (WUMED or EXP-301). OSED is one of the three certifications which make up the new OSCE3. The course focuses on exploit development, covering topics such as buffer/SEH overflows, DEP/ASLR bypasses, custom shellcode, and format string exploits.


## My background
I've never felt confident in my binary exploitation skills, even though [I passed the exam for the old OSCE](/offsec-ctp-osce-review) and I took a course on binary exploitation from a pwn god. Most pwn and rev CTF tasks seemed too hard to solve for my small, shrunken monkey brain (this sentence was suggested by my sister) (also, I've always preferred web challs). That being said, I knew how to use a debugger/disassembler and how to read and write assembly code before my lab started, which was a significant advantage.


## Prerequisites
While the course was labeled 'intermediate-level' by Offensive Security, I wouldn't advise any beginners to enroll unless they've got a few basic skills beforehand. Here's the prerequisites OffSec lists on their site:

<center><img src="/images/wumed/prereqs.png"></center>

I was familiar with all of the concepts presented in the [course syllabus](https://www.offensive-security.com/documentation/EXP301-syllabus.pdf). It would be a good idea to watch [this series from LiveOverflow](https://youtube.com/playlist?list=PLhixgUqwRTjxglIswKp9mpkfPNfHkzyeN) before you start your lab - at least the first few videos.

## The course
The EXP-301 course has received a lot of criticism since it has been launched. A lot of people seem to be very upset by the fact that it only covers x86 Windows exploits. I'd say it doesn't matter - after all, is a Windows x86 buffer overflow exploit that different from a Linux x64 buffer overflow? The registers and some instructions might be different, but the core concepts are the same. I would be very disappointed if the course covered buffer overflows for 32-bit programs and then re-taught them for 64-bit apps - that would be a waste of course manual pages.

Another criticized aspect is the choice of the decompiler. There's nothing wrong with IDA Pro, but the course teaches reverse engineering using the free version - that means no C pseudo-code, just raw assembly. While this is a very good way to learn how to read assembly code, I have to agree with the others on this one - teaching reversing to beginner exploit developers without C pseudo-code is a little bit too hard, even for an OffSec course.

That being said, the course is very enjoyable. The course manual is well-written and the videos are very easy to understand. I ended up solving most of the extra-miles (except a few hard ones), but I didn't have enough time to solve the three challenges at the end of the course - make sure you leave enough time for those when making a schedule for your lab time; you won't manage to solve all of them in a few days!

## The exam
Ouch. This exam has been the hardest I've ever taken. No wonder there are only 13 OSEDs on the Discord server (as of July 6th). However, if you take your time, understand everything presented in the course, do the exercises and take notes, I'm pretty sure you'll pass on your first try.

As outlined in the [OSED Exam Guide](https://help.offensive-security.com/hc/en-us/articles/360052977212-OSED-Exam-Guide), the exam consists of 3 assignments. You need to solve two of them in order to pass, but only full completion of tasks will be awarded. The exam is about two days long.

Unfortunately, I was unable to compile a timeline from the scattered notes that I made during the exam. However, I will try to tell you about my exam experience. I connected to the proctoring software at 9:50 AM and began my exam 15 minutes later. I read all the assignment prompts a few times and concluded that I could solve the first two assignments in about 8 hours. However, things didn't go according to plan. I managed to finish the 1st assignment on the 2nd day, at about 19:00 - the assignment was a lot harder than I'd initially thought. Thankfully, the 2nd assignment was easier and I managed to solve it at 6:00 AM, about 4 hours before my exam was supposed to end. I wrote my report, submitted it at about 11:30 AM, and then waited for the results to arrive for around 7 days.

## Exam Tips
 * **TAKE BREAKS**: For some reason, the WinDbg font is very tiring for my eyes (am I the only one?). You'll face a lot of obstacles during the exam and taking breaks will help clear your mind. The final solution for the assignments requires a lot of tricks, and I've figured all of them out during or closely after a break.
 * Make sure you read the assigments carefully: It would be a shame to fail the exam just because you didn't include a screenshot.
 * Use comments: Comment all parts of your code, including ROP gadgets or assembly code (if you use those). Your scripts will suffer so many changes that you might end up not knowing what part of your code does - you don't want to be put in the position of reverse-engineering your own code.
 * [Receive good vibes from a pwn master](https://twitter.com/epi052/status/1405647196331167753?s=20)
 * Use your course notes: If you've taken notes during the course, use them! Almost everything you need was thaught in the course.
 * Most importantly: Take regular breaks.

## Conclusion
The course was 100% worth it for me. I'm now more confident in my exploit creation skills and on my way to earning OSCE3 (does owning OSCE make it OSCE4? Also, where's OSCE2?). 

Now, if you'll excuse me, I have to let my scholastic aptitude rest because I'm finally done with that bloody test.

Until next time, hack the world.

yakuhito, over.